// Syscall dispatch — routes seccomp notifications to handlers.
//
// Each intercepted syscall has both a modern *at variant and a legacy variant.
// Legacy syscalls (mkdir, unlink, chmod, ...) don't have a dirfd argument —
// they implicitly use AT_FDCWD. We handle both uniformly.
//
// COW-able:  openat, mkdirat/mkdir, renameat2/rename, symlinkat/symlink,
//            fchmodat/chmod, truncate
// DENY-only: unlinkat/unlink/rmdir, linkat/link, fchownat/chown/lchown

use std::os::unix::io::RawFd;
use std::path::PathBuf;

use crate::cow::CowTable;
use crate::notif::{self, SeccompNotif};
use crate::path;
use crate::whitelist::Whitelist;

/// Handle a single seccomp notification (already received by caller).
pub fn handle_notification(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let nr = req.data.nr as i64;

    match nr {
        // openat — COW via fd injection
        n if n == libc::SYS_openat => {
            handle_openat(notify_fd, req, cow, whitelist);
        }

        // mkdir family — COW
        n if n == libc::SYS_mkdirat || n == libc::SYS_mkdir as i64 => {
            handle_mkdir(notify_fd, req, cow, whitelist);
        }

        // rename family — COW
        n if n == libc::SYS_renameat2 || n == libc::SYS_rename as i64 => {
            handle_rename(notify_fd, req, cow, whitelist);
        }

        // symlink family — COW
        n if n == libc::SYS_symlinkat || n == libc::SYS_symlink as i64 => {
            handle_symlink(notify_fd, req, cow, whitelist);
        }

        // chmod family — COW
        n if n == libc::SYS_fchmodat || n == libc::SYS_chmod as i64 => {
            handle_chmod(notify_fd, req, cow, whitelist);
        }

        // truncate — COW
        n if n == libc::SYS_truncate => {
            handle_truncate(notify_fd, req, cow, whitelist);
        }

        // unlink/rmdir family — DENY only
        n if n == libc::SYS_unlinkat
            || n == libc::SYS_unlink as i64
            || n == libc::SYS_rmdir as i64 =>
        {
            handle_deny_write(notify_fd, req, whitelist, syscall_name(nr));
        }

        // link family — DENY only
        n if n == libc::SYS_linkat || n == libc::SYS_link as i64 => {
            handle_deny_write(notify_fd, req, whitelist, syscall_name(nr));
        }

        // chown family — DENY only
        n if n == libc::SYS_fchownat
            || n == libc::SYS_chown as i64
            || n == libc::SYS_lchown as i64 =>
        {
            handle_deny_write(notify_fd, req, whitelist, syscall_name(nr));
        }

        // Unknown — allow
        _ => {
            let _ = notif::respond_continue(notify_fd, req.id);
        }
    }
}

// ================================================================
// Syscall name for logging
// ================================================================

fn syscall_name(nr: i64) -> &'static str {
    match nr {
        n if n == libc::SYS_openat => "openat",
        n if n == libc::SYS_mkdirat => "mkdirat",
        n if n == libc::SYS_mkdir as i64 => "mkdir(legacy)",
        n if n == libc::SYS_renameat2 => "renameat2",
        n if n == libc::SYS_rename as i64 => "rename(legacy)",
        n if n == libc::SYS_symlinkat => "symlinkat",
        n if n == libc::SYS_symlink as i64 => "symlink(legacy)",
        n if n == libc::SYS_linkat => "linkat",
        n if n == libc::SYS_link as i64 => "link(legacy)",
        n if n == libc::SYS_fchmodat => "fchmodat",
        n if n == libc::SYS_chmod as i64 => "chmod(legacy)",
        n if n == libc::SYS_fchownat => "fchownat",
        n if n == libc::SYS_chown as i64 => "chown(legacy)",
        n if n == libc::SYS_lchown as i64 => "lchown(legacy)",
        n if n == libc::SYS_unlinkat => "unlinkat",
        n if n == libc::SYS_unlink as i64 => "unlink(legacy)",
        n if n == libc::SYS_rmdir as i64 => "rmdir(legacy)",
        n if n == libc::SYS_truncate => "truncate",
        _ => "unknown",
    }
}

// ================================================================
// Resolve helpers: modern *at vs legacy
// ================================================================

/// Resolve a single-path syscall. Handles both modern (dirfd+path) and
/// legacy (path-only) argument layouts.
///
/// Modern:  args[0]=dirfd, args[1]=path_ptr
/// Legacy:  args[0]=path_ptr (dirfd implied AT_FDCWD)
fn resolve_path_auto(req: &SeccompNotif, notify_fd: RawFd) -> Option<String> {
    let nr = req.data.nr as i64;
    let args = &req.data.args;

    // Determine (dirfd, path_addr) based on modern vs legacy
    let (dirfd, path_addr) = if is_legacy_single_path(nr) {
        (libc::AT_FDCWD, args[0])
    } else if nr == libc::SYS_truncate {
        (libc::AT_FDCWD, args[0])
    } else if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath): linkpath is args[1]:args[2]
        (args[1] as i32, args[2])
    } else {
        // Standard *at: args[0]=dirfd, args[1]=path
        (args[0] as i32, args[1])
    };

    let raw = path::read_proc_mem(req.pid, path_addr, libc::PATH_MAX as usize).ok()?;
    let resolved = path::resolve_at_path(req.pid, dirfd, &raw).ok()?;

    if notif::id_valid(notify_fd, req.id).is_err() {
        return None;
    }

    Some(resolved.to_string_lossy().to_string())
}

/// Is this a legacy single-path syscall (no dirfd)?
/// mkdir, unlink, rmdir, chmod, chown, lchown, truncate
fn is_legacy_single_path(nr: i64) -> bool {
    nr == libc::SYS_mkdir as i64
        || nr == libc::SYS_unlink as i64
        || nr == libc::SYS_rmdir as i64
        || nr == libc::SYS_chmod as i64
        || nr == libc::SYS_chown as i64
        || nr == libc::SYS_lchown as i64
}

/// Resolve a two-path syscall (rename, link, symlink).
/// Returns (src_path, dst_path).
fn resolve_two_paths(
    req: &SeccompNotif,
    notify_fd: RawFd,
) -> Option<(String, String)> {
    let nr = req.data.nr as i64;
    let args = &req.data.args;

    let (src_dirfd, src_addr, dst_dirfd, dst_addr) = if nr == libc::SYS_rename as i64
        || nr == libc::SYS_link as i64
    {
        // legacy: rename(old, new) / link(old, new)
        (libc::AT_FDCWD, args[0], libc::AT_FDCWD, args[1])
    } else if nr == libc::SYS_symlink as i64 {
        // legacy: symlink(target, linkpath)
        (libc::AT_FDCWD, args[0], libc::AT_FDCWD, args[1])
    } else if nr == libc::SYS_renameat2 {
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        (args[0] as i32, args[1], args[2] as i32, args[3])
    } else if nr == libc::SYS_linkat {
        // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        (args[0] as i32, args[1], args[2] as i32, args[3])
    } else if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath)
        (libc::AT_FDCWD, args[0], args[1] as i32, args[2])
    } else {
        return None;
    };

    let src_raw = path::read_proc_mem(req.pid, src_addr, libc::PATH_MAX as usize).ok()?;
    let src = path::resolve_at_path(req.pid, src_dirfd, &src_raw).ok()?;

    let dst_raw = path::read_proc_mem(req.pid, dst_addr, libc::PATH_MAX as usize).ok()?;
    let dst = path::resolve_at_path(req.pid, dst_dirfd, &dst_raw).ok()?;

    if notif::id_valid(notify_fd, req.id).is_err() {
        return None;
    }

    Some((
        src.to_string_lossy().to_string(),
        dst.to_string_lossy().to_string(),
    ))
}

// ================================================================
// openat — COW via fd injection (unchanged)
// ================================================================

fn handle_openat(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let args = &req.data.args;
    let open_flags = args[2] as i32;
    let mode = if open_flags & libc::O_CREAT != 0 {
        args[3] as i32
    } else {
        0o644
    };
    let dirfd = args[0] as i32;

    let raw_path = match path::read_proc_mem(req.pid, args[1], libc::PATH_MAX as usize) {
        Ok(p) => p,
        Err(_) => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    let resolved = match path::resolve_at_path(req.pid, dirfd, &raw_path) {
        Ok(p) => p,
        Err(_) => PathBuf::from(&raw_path),
    };
    let path_str = resolved.to_string_lossy();

    if notif::id_valid(notify_fd, req.id).is_err() {
        return;
    }

    if path_str.starts_with("/dev/") {
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let accmode = open_flags & libc::O_ACCMODE;
    let mode_str = match accmode {
        libc::O_RDONLY => "R",
        libc::O_WRONLY => "W",
        _ => "RW",
    };

    // Deleted in COW layer?
    if cow.is_deleted(&path_str) {
        if open_flags & libc::O_CREAT != 0 && accmode != libc::O_RDONLY {
            if cow.materialize(&path_str, open_flags, mode as u32).is_ok() {
                if let Some(cow_path) = cow.lookup(&path_str) {
                    if cow.inject_fd(notify_fd, req.id, cow_path, open_flags, mode).is_ok() {
                        return;
                    }
                }
            }
        }
        let _ = notif::respond_errno(notify_fd, req.id, libc::ENOENT);
        return;
    }

    // COW-HIT
    if let Some(cow_path) = cow.lookup(&path_str) {
        eprintln!(
            "[supervisor] COW-HIT openat({}, {}) -> {} pid={}",
            path_str,
            mode_str,
            cow_path.display(),
            req.pid
        );
        match cow.inject_fd(notify_fd, req.id, cow_path, open_flags, mode) {
            Ok(_) => return,
            Err(e) => {
                eprintln!("[supervisor] COW inject failed: {}", e);
                let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
                return;
            }
        }
    }

    // Whitelist check
    if whitelist.check_path(&path_str, open_flags) {
        eprintln!(
            "[supervisor] ALLOW openat({}, {}) pid={}",
            path_str, mode_str, req.pid
        );
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    // Denied write → COW
    if accmode != libc::O_RDONLY {
        eprintln!(
            "[supervisor] COW-NEW openat({}, {}) pid={}",
            path_str, mode_str, req.pid
        );
        if cow.materialize(&path_str, open_flags, mode as u32).is_ok() {
            if let Some(cow_path) = cow.lookup(&path_str) {
                if cow.inject_fd(notify_fd, req.id, cow_path, open_flags, mode).is_ok() {
                    return;
                }
            }
        }
    }

    eprintln!(
        "[supervisor] DENY  openat({}, {}) pid={}",
        path_str, mode_str, req.pid
    );
    let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
}

// ================================================================
// mkdir/mkdirat — COW: create dir in cow_files/
// ================================================================

fn handle_mkdir(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let nr = req.data.nr as i64;
    let name = syscall_name(nr);
    let args = &req.data.args;

    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW {}({}) pid={}", name, path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    // mode: mkdirat → args[2], mkdir → args[1]
    let mode = if nr == libc::SYS_mkdir as i64 {
        args[1] as u32
    } else {
        args[2] as u32
    };

    match cow.cow_mkdir(&path_str, mode) {
        Ok(()) => {
            eprintln!(
                "[supervisor] COW   {}({}, {:o}) pid={}",
                name, path_str, mode, req.pid
            );
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!(
                "[supervisor] DENY  {}({}) pid={} — COW failed: {}",
                name, path_str, req.pid, e
            );
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// rename/renameat2 — COW: rename within cow_files/
// ================================================================

fn handle_rename(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let name = syscall_name(req.data.nr as i64);

    let (src_str, dst_str) = match resolve_two_paths(req, notify_fd) {
        Some(p) => p,
        None => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    if whitelist.is_write_allowed(&src_str) && whitelist.is_write_allowed(&dst_str) {
        eprintln!(
            "[supervisor] ALLOW {}({} -> {}) pid={}",
            name, src_str, dst_str, req.pid
        );
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    match cow.cow_rename(&src_str, &dst_str) {
        Ok(()) => {
            eprintln!(
                "[supervisor] COW   {}({} -> {}) pid={}",
                name, src_str, dst_str, req.pid
            );
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!(
                "[supervisor] DENY  {}({} -> {}) pid={} — COW failed: {}",
                name, src_str, dst_str, req.pid, e
            );
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// symlink/symlinkat — COW: create symlink in cow_files/
// ================================================================

fn handle_symlink(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let nr = req.data.nr as i64;
    let name = syscall_name(nr);
    let args = &req.data.args;

    // symlink(target, linkpath):   args[0]=target, args[1]=linkpath
    // symlinkat(target, dirfd, linkpath): args[0]=target, args[1]=dirfd, args[2]=linkpath
    let target = match path::read_proc_mem(req.pid, args[0], libc::PATH_MAX as usize) {
        Ok(p) => p,
        Err(_) => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    let (link_dirfd, link_addr) = if nr == libc::SYS_symlink as i64 {
        (libc::AT_FDCWD, args[1])
    } else {
        (args[1] as i32, args[2])
    };

    let link_raw = match path::read_proc_mem(req.pid, link_addr, libc::PATH_MAX as usize) {
        Ok(p) => p,
        Err(_) => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };
    let linkpath = match path::resolve_at_path(req.pid, link_dirfd, &link_raw) {
        Ok(p) => p,
        Err(_) => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };
    let link_str = linkpath.to_string_lossy().to_string();

    if notif::id_valid(notify_fd, req.id).is_err() {
        return;
    }

    if whitelist.is_write_allowed(&link_str) {
        eprintln!(
            "[supervisor] ALLOW {}({} -> {}) pid={}",
            name, link_str, target, req.pid
        );
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    match cow.cow_symlink(&target, &link_str) {
        Ok(()) => {
            eprintln!(
                "[supervisor] COW   {}({} -> {}) pid={}",
                name, link_str, target, req.pid
            );
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!(
                "[supervisor] DENY  {}({}) pid={} — COW failed: {}",
                name, link_str, req.pid, e
            );
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// chmod/fchmodat — COW: materialize then chmod copy
// ================================================================

fn handle_chmod(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let nr = req.data.nr as i64;
    let name = syscall_name(nr);
    let args = &req.data.args;

    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW {}({}) pid={}", name, path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    // mode: fchmodat → args[2], chmod → args[1]
    let mode = if nr == libc::SYS_chmod as i64 {
        args[1] as u32
    } else {
        args[2] as u32
    };

    match cow.cow_chmod(&path_str, mode) {
        Ok(()) => {
            eprintln!(
                "[supervisor] COW   {}({}, {:o}) pid={}",
                name, path_str, mode, req.pid
            );
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!(
                "[supervisor] DENY  {}({}) pid={} — COW failed: {}",
                name, path_str, req.pid, e
            );
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// truncate — COW: materialize then truncate copy
// ================================================================

fn handle_truncate(
    notify_fd: RawFd,
    req: &SeccompNotif,
    cow: &mut CowTable,
    whitelist: &Whitelist,
) {
    let args = &req.data.args;

    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!(
            "[supervisor] ALLOW truncate({}) pid={}",
            path_str, req.pid
        );
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let length = args[1] as i64;
    match cow.cow_truncate(&path_str, length) {
        Ok(()) => {
            eprintln!(
                "[supervisor] COW   truncate({}, {}) pid={}",
                path_str, length, req.pid
            );
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!(
                "[supervisor] DENY  truncate({}) pid={} — COW failed: {}",
                path_str, req.pid, e
            );
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// DENY-only: unlink/rmdir, link, chown
// ================================================================

fn handle_deny_write(
    notify_fd: RawFd,
    req: &SeccompNotif,
    whitelist: &Whitelist,
    name: &str,
) {
    let nr = req.data.nr as i64;

    // Two-path syscalls: linkat, link
    if nr == libc::SYS_linkat || nr == libc::SYS_link as i64 {
        let (src, dst) = match resolve_two_paths(req, notify_fd) {
            Some(p) => p,
            None => {
                let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
                return;
            }
        };
        if whitelist.is_write_allowed(&src) && whitelist.is_write_allowed(&dst) {
            eprintln!(
                "[supervisor] ALLOW {}({} -> {}) pid={}",
                name, src, dst, req.pid
            );
            let _ = notif::respond_continue(notify_fd, req.id);
            return;
        }
        eprintln!(
            "[supervisor] DENY  {}({} -> {}) pid={} — hard links outside whitelist not allowed",
            name, src, dst, req.pid
        );
        let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        return;
    }

    // Single-path syscalls
    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => {
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
            return;
        }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW {}({}) pid={}", name, path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    // Descriptive deny messages per syscall family
    let reason = match nr {
        n if n == libc::SYS_unlinkat || n == libc::SYS_unlink as i64 => {
            "file deletion outside whitelist not allowed"
        }
        n if n == libc::SYS_rmdir as i64 => {
            "directory removal outside whitelist not allowed"
        }
        n if n == libc::SYS_fchownat
            || n == libc::SYS_chown as i64
            || n == libc::SYS_lchown as i64 =>
        {
            "ownership change outside whitelist not allowed (requires CAP_CHOWN)"
        }
        _ => "operation outside whitelist not allowed",
    };

    eprintln!(
        "[supervisor] DENY  {}({}) pid={} — {}",
        name, path_str, req.pid, reason
    );
    let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
}
