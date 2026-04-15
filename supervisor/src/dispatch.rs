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

use crate::cow::{self, CowTable};
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
        n if n == libc::SYS_openat => handle_openat(notify_fd, req, cow, whitelist),

        // mkdir — COW
        n if n == libc::SYS_mkdirat || n == libc::SYS_mkdir as i64 => {
            handle_mkdir(notify_fd, req, cow, whitelist);
        }
        // rename — COW
        n if n == libc::SYS_renameat2 || n == libc::SYS_rename as i64 => {
            handle_rename(notify_fd, req, cow, whitelist);
        }
        // symlink — COW
        n if n == libc::SYS_symlinkat || n == libc::SYS_symlink as i64 => {
            handle_symlink(notify_fd, req, cow, whitelist);
        }
        // chmod — COW
        n if n == libc::SYS_fchmodat || n == libc::SYS_chmod as i64 => {
            handle_chmod(notify_fd, req, cow, whitelist);
        }
        // truncate — COW
        n if n == libc::SYS_truncate => handle_truncate(notify_fd, req, cow, whitelist),

        // DENY-only
        n if n == libc::SYS_unlinkat
            || n == libc::SYS_unlink as i64
            || n == libc::SYS_rmdir as i64 =>
        {
            handle_deny_write(notify_fd, req, whitelist, syscall_name(nr));
        }
        n if n == libc::SYS_linkat || n == libc::SYS_link as i64 => {
            handle_deny_write(notify_fd, req, whitelist, syscall_name(nr));
        }
        n if n == libc::SYS_fchownat
            || n == libc::SYS_chown as i64
            || n == libc::SYS_lchown as i64 =>
        {
            handle_deny_write(notify_fd, req, whitelist, syscall_name(nr));
        }

        _ => { let _ = notif::respond_continue(notify_fd, req.id); }
    }
}

// ================================================================
// Helpers
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

fn resolve_path_auto(req: &SeccompNotif, notify_fd: RawFd) -> Option<String> {
    let nr = req.data.nr as i64;
    let args = &req.data.args;

    let (dirfd, path_addr) = if is_legacy_single_path(nr) {
        (libc::AT_FDCWD, args[0])
    } else if nr == libc::SYS_truncate {
        (libc::AT_FDCWD, args[0])
    } else if nr == libc::SYS_symlinkat {
        (args[1] as i32, args[2])
    } else {
        (args[0] as i32, args[1])
    };

    let raw = path::read_proc_mem(req.pid, path_addr, libc::PATH_MAX as usize).ok()?;
    let resolved = path::resolve_at_path(req.pid, dirfd, &raw).ok()?;
    if notif::id_valid(notify_fd, req.id).is_err() { return None; }
    Some(resolved.to_string_lossy().to_string())
}

fn is_legacy_single_path(nr: i64) -> bool {
    nr == libc::SYS_mkdir as i64
        || nr == libc::SYS_unlink as i64
        || nr == libc::SYS_rmdir as i64
        || nr == libc::SYS_chmod as i64
        || nr == libc::SYS_chown as i64
        || nr == libc::SYS_lchown as i64
}

fn resolve_two_paths(req: &SeccompNotif, notify_fd: RawFd) -> Option<(String, String)> {
    let nr = req.data.nr as i64;
    let args = &req.data.args;

    let (sd, sa, dd, da) = if nr == libc::SYS_rename as i64 || nr == libc::SYS_link as i64 {
        (libc::AT_FDCWD, args[0], libc::AT_FDCWD, args[1])
    } else if nr == libc::SYS_symlink as i64 {
        (libc::AT_FDCWD, args[0], libc::AT_FDCWD, args[1])
    } else if nr == libc::SYS_renameat2 || nr == libc::SYS_linkat {
        (args[0] as i32, args[1], args[2] as i32, args[3])
    } else if nr == libc::SYS_symlinkat {
        (libc::AT_FDCWD, args[0], args[1] as i32, args[2])
    } else {
        return None;
    };

    let sr = path::read_proc_mem(req.pid, sa, libc::PATH_MAX as usize).ok()?;
    let s = path::resolve_at_path(req.pid, sd, &sr).ok()?;
    let dr = path::read_proc_mem(req.pid, da, libc::PATH_MAX as usize).ok()?;
    let d = path::resolve_at_path(req.pid, dd, &dr).ok()?;
    if notif::id_valid(notify_fd, req.id).is_err() { return None; }
    Some((s.to_string_lossy().to_string(), d.to_string_lossy().to_string()))
}

// ================================================================
// openat — COW via fd injection
// ================================================================

fn handle_openat(notify_fd: RawFd, req: &SeccompNotif, cow: &mut CowTable, whitelist: &Whitelist) {
    let args = &req.data.args;
    let open_flags = args[2] as i32;
    let mode = if open_flags & libc::O_CREAT != 0 { args[3] as i32 } else { 0o644 };
    let dirfd = args[0] as i32;

    let raw_path = match path::read_proc_mem(req.pid, args[1], libc::PATH_MAX as usize) {
        Ok(p) => p,
        Err(_) => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };
    let resolved = match path::resolve_at_path(req.pid, dirfd, &raw_path) {
        Ok(p) => p,
        Err(_) => PathBuf::from(&raw_path),
    };
    let path_str = resolved.to_string_lossy();

    if notif::id_valid(notify_fd, req.id).is_err() { return; }
    if path_str.starts_with("/dev/") {
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let accmode = open_flags & libc::O_ACCMODE;
    let mode_str = match accmode { libc::O_RDONLY => "R", libc::O_WRONLY => "W", _ => "RW" };

    if cow.is_deleted(&path_str) {
        if open_flags & libc::O_CREAT != 0 && accmode != libc::O_RDONLY {
            let cmd = cow::read_command_context(req.pid);
            if cow.materialize(&path_str, open_flags, mode as u32, "openat", &cmd).is_ok() {
                if let Some(cp) = cow.lookup(&path_str) {
                    if cow.inject_fd(notify_fd, req.id, cp, open_flags, mode).is_ok() { return; }
                }
            }
        }
        let _ = notif::respond_errno(notify_fd, req.id, libc::ENOENT);
        return;
    }

    if let Some(cp) = cow.lookup(&path_str) {
        eprintln!("[supervisor] COW-HIT openat({}, {}) -> {} pid={}", path_str, mode_str, cp.display(), req.pid);
        match cow.inject_fd(notify_fd, req.id, cp, open_flags, mode) {
            Ok(_) => return,
            Err(e) => { eprintln!("[supervisor] COW inject failed: {}", e); let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
        }
    }

    if whitelist.check_path(&path_str, open_flags) {
        eprintln!("[supervisor] ALLOW openat({}, {}) pid={}", path_str, mode_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    if accmode != libc::O_RDONLY {
        let cmd = cow::read_command_context(req.pid);
        eprintln!("[supervisor] COW-NEW openat({}, {}) pid={}", path_str, mode_str, req.pid);
        if cow.materialize(&path_str, open_flags, mode as u32, "openat", &cmd).is_ok() {
            if let Some(cp) = cow.lookup(&path_str) {
                if cow.inject_fd(notify_fd, req.id, cp, open_flags, mode).is_ok() { return; }
            }
        }
    }

    eprintln!("[supervisor] DENY  openat({}, {}) pid={}", path_str, mode_str, req.pid);
    let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
}

// ================================================================
// mkdir — COW
// ================================================================

fn handle_mkdir(notify_fd: RawFd, req: &SeccompNotif, cow: &mut CowTable, whitelist: &Whitelist) {
    let nr = req.data.nr as i64;
    let name = syscall_name(nr);

    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW {}({}) pid={}", name, path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let mode = if nr == libc::SYS_mkdir as i64 { req.data.args[1] as u32 } else { req.data.args[2] as u32 };
    let cmd = cow::read_command_context(req.pid);

    match cow.cow_mkdir(&path_str, mode, name, &cmd) {
        Ok(()) => {
            eprintln!("[supervisor] COW   {}({}, {:o}) pid={}", name, path_str, mode, req.pid);
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!("[supervisor] DENY  {}({}) pid={} — COW failed: {}", name, path_str, req.pid, e);
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// rename — COW
// ================================================================

fn handle_rename(notify_fd: RawFd, req: &SeccompNotif, cow: &mut CowTable, whitelist: &Whitelist) {
    let name = syscall_name(req.data.nr as i64);

    let (src, dst) = match resolve_two_paths(req, notify_fd) {
        Some(p) => p,
        None => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };

    if whitelist.is_write_allowed(&src) && whitelist.is_write_allowed(&dst) {
        eprintln!("[supervisor] ALLOW {}({} -> {}) pid={}", name, src, dst, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let cmd = cow::read_command_context(req.pid);
    match cow.cow_rename(&src, &dst, name, &cmd) {
        Ok(()) => {
            eprintln!("[supervisor] COW   {}({} -> {}) pid={}", name, src, dst, req.pid);
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!("[supervisor] DENY  {}({} -> {}) pid={} — COW failed: {}", name, src, dst, req.pid, e);
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// symlink — COW
// ================================================================

fn handle_symlink(notify_fd: RawFd, req: &SeccompNotif, cow: &mut CowTable, whitelist: &Whitelist) {
    let nr = req.data.nr as i64;
    let name = syscall_name(nr);
    let args = &req.data.args;

    let target = match path::read_proc_mem(req.pid, args[0], libc::PATH_MAX as usize) {
        Ok(p) => p,
        Err(_) => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };

    let (link_dirfd, link_addr) = if nr == libc::SYS_symlink as i64 {
        (libc::AT_FDCWD, args[1])
    } else {
        (args[1] as i32, args[2])
    };

    let link_raw = match path::read_proc_mem(req.pid, link_addr, libc::PATH_MAX as usize) {
        Ok(p) => p,
        Err(_) => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };
    let linkpath = match path::resolve_at_path(req.pid, link_dirfd, &link_raw) {
        Ok(p) => p,
        Err(_) => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };
    let link_str = linkpath.to_string_lossy().to_string();

    if notif::id_valid(notify_fd, req.id).is_err() { return; }

    if whitelist.is_write_allowed(&link_str) {
        eprintln!("[supervisor] ALLOW {}({} -> {}) pid={}", name, link_str, target, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let cmd = cow::read_command_context(req.pid);
    match cow.cow_symlink(&target, &link_str, name, &cmd) {
        Ok(()) => {
            eprintln!("[supervisor] COW   {}({} -> {}) pid={}", name, link_str, target, req.pid);
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!("[supervisor] DENY  {}({}) pid={} — COW failed: {}", name, link_str, req.pid, e);
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// chmod — COW
// ================================================================

fn handle_chmod(notify_fd: RawFd, req: &SeccompNotif, cow: &mut CowTable, whitelist: &Whitelist) {
    let nr = req.data.nr as i64;
    let name = syscall_name(nr);

    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW {}({}) pid={}", name, path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let mode = if nr == libc::SYS_chmod as i64 { req.data.args[1] as u32 } else { req.data.args[2] as u32 };
    let cmd = cow::read_command_context(req.pid);

    match cow.cow_chmod(&path_str, mode, name, &cmd) {
        Ok(()) => {
            eprintln!("[supervisor] COW   {}({}, {:o}) pid={}", name, path_str, mode, req.pid);
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!("[supervisor] DENY  {}({}) pid={} — COW failed: {}", name, path_str, req.pid, e);
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// truncate — COW
// ================================================================

fn handle_truncate(notify_fd: RawFd, req: &SeccompNotif, cow: &mut CowTable, whitelist: &Whitelist) {
    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW truncate({}) pid={}", path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let length = req.data.args[1] as i64;
    let cmd = cow::read_command_context(req.pid);

    match cow.cow_truncate(&path_str, length, "truncate", &cmd) {
        Ok(()) => {
            eprintln!("[supervisor] COW   truncate({}, {}) pid={}", path_str, length, req.pid);
            let _ = notif::respond_value(notify_fd, req.id, 0);
        }
        Err(e) => {
            eprintln!("[supervisor] DENY  truncate({}) pid={} — COW failed: {}", path_str, req.pid, e);
            let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        }
    }
}

// ================================================================
// DENY-only handlers
// ================================================================

fn handle_deny_write(notify_fd: RawFd, req: &SeccompNotif, whitelist: &Whitelist, name: &str) {
    let nr = req.data.nr as i64;

    if nr == libc::SYS_linkat || nr == libc::SYS_link as i64 {
        let (src, dst) = match resolve_two_paths(req, notify_fd) {
            Some(p) => p,
            None => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
        };
        if whitelist.is_write_allowed(&src) && whitelist.is_write_allowed(&dst) {
            eprintln!("[supervisor] ALLOW {}({} -> {}) pid={}", name, src, dst, req.pid);
            let _ = notif::respond_continue(notify_fd, req.id);
            return;
        }
        eprintln!("[supervisor] DENY  {}({} -> {}) pid={} — hard links outside whitelist not allowed", name, src, dst, req.pid);
        let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
        return;
    }

    let path_str = match resolve_path_auto(req, notify_fd) {
        Some(p) => p,
        None => { let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES); return; }
    };

    if whitelist.is_write_allowed(&path_str) {
        eprintln!("[supervisor] ALLOW {}({}) pid={}", name, path_str, req.pid);
        let _ = notif::respond_continue(notify_fd, req.id);
        return;
    }

    let reason = match nr {
        n if n == libc::SYS_unlinkat || n == libc::SYS_unlink as i64 => "file deletion outside whitelist not allowed",
        n if n == libc::SYS_rmdir as i64 => "directory removal outside whitelist not allowed",
        n if n == libc::SYS_fchownat || n == libc::SYS_chown as i64 || n == libc::SYS_lchown as i64 => {
            "ownership change outside whitelist not allowed (requires CAP_CHOWN)"
        }
        _ => "operation outside whitelist not allowed",
    };

    eprintln!("[supervisor] DENY  {}({}) pid={} — {}", name, path_str, req.pid, reason);
    let _ = notif::respond_errno(notify_fd, req.id, libc::EACCES);
}
