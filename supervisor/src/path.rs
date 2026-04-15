// Path resolution helpers — read process memory and resolve paths.
//
// Reads null-terminated strings from /proc/{pid}/mem, resolves relative
// paths using /proc/{pid}/cwd or /proc/{pid}/fd/{dirfd}, and normalizes
// the result.

use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::RawFd;
use std::path::{Component, Path, PathBuf};

use crate::notif::SeccompNotif;

/// Read a null-terminated string from the target process memory.
///
/// Opens /proc/{pid}/mem, seeks to `addr`, reads up to `max_len` bytes,
/// and returns everything before the first NUL.
pub fn read_proc_mem(pid: u32, addr: u64, max_len: usize) -> io::Result<String> {
    let proc_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&proc_path)?;
    file.seek(SeekFrom::Start(addr))?;

    let mut buf = vec![0u8; max_len];
    let n = file.read(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty read"));
    }

    let nul_pos = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    String::from_utf8(buf[..nul_pos].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Normalize a path: collapse `.`, `..`, and consecutive slashes.
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    let is_absolute = path.is_absolute();
    if is_absolute {
        result.push("/");
    }

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(part) => result.push(part),
            Component::Prefix(_) => {}
        }
    }

    if result.as_os_str().is_empty() {
        if is_absolute {
            PathBuf::from("/")
        } else {
            PathBuf::from(".")
        }
    } else {
        result
    }
}

/// Resolve a (dirfd, raw_path) pair to an absolute normalized path.
///
/// Uses the target process's /proc entries:
/// - If raw_path is absolute, normalize and return.
/// - If dirfd == AT_FDCWD (-100), use /proc/{pid}/cwd as base.
/// - Otherwise, use /proc/{pid}/fd/{dirfd} as base.
pub fn resolve_at_path(pid: u32, dirfd: i32, raw_path: &str) -> io::Result<PathBuf> {
    let p = Path::new(raw_path);
    if p.is_absolute() {
        return Ok(normalize_path(p));
    }

    let base = if dirfd == libc::AT_FDCWD {
        std::fs::read_link(format!("/proc/{}/cwd", pid))?
    } else if dirfd >= 0 {
        std::fs::read_link(format!("/proc/{}/fd/{}", pid, dirfd))?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid dirfd: {}", dirfd),
        ));
    };

    Ok(normalize_path(&base.join(raw_path)))
}

/// Resolve the primary path from a seccomp notification.
///
/// Reads the path argument from child memory and resolves it to an absolute
/// path. The argument position depends on the syscall:
///
/// | Syscall      | dirfd     | path     |
/// |------------- |-----------|----------|
/// | openat       | args[0]   | args[1]  |
/// | unlinkat     | args[0]   | args[1]  |
/// | mkdirat      | args[0]   | args[1]  |
/// | renameat2    | args[0]   | args[1]  |  (source)
/// | symlinkat    | args[1]   | args[2]  |  (linkpath)
/// | linkat       | args[0]   | args[1]  |  (source)
/// | fchmodat     | args[0]   | args[1]  |
/// | fchownat     | args[0]   | args[1]  |
/// | truncate     | AT_FDCWD  | args[0]  |
pub fn resolve_notif_path(notif: &SeccompNotif, _notify_fd: RawFd) -> io::Result<PathBuf> {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    let (dirfd, path_addr) = match nr {
        n if n == libc::SYS_truncate => (libc::AT_FDCWD, args[0]),
        n if n == libc::SYS_symlinkat => (args[1] as i32, args[2]),
        _ => {
            // openat, unlinkat, mkdirat, renameat2, linkat, fchmodat, fchownat
            (args[0] as i32, args[1])
        }
    };

    let raw = read_proc_mem(notif.pid, path_addr, libc::PATH_MAX as usize)?;
    resolve_at_path(notif.pid, dirfd, &raw)
}

/// Resolve the second (destination) path for two-path syscalls.
///
/// | Syscall    | dirfd2   | path2    |
/// |------------|----------|----------|
/// | renameat2  | args[2]  | args[3]  |
/// | linkat     | args[2]  | args[3]  |
///
/// Returns None for single-path syscalls.
pub fn resolve_notif_second_path(
    notif: &SeccompNotif,
    _notify_fd: RawFd,
) -> Option<io::Result<PathBuf>> {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;

    let (dirfd, path_addr) = match nr {
        n if n == libc::SYS_renameat2 || n == libc::SYS_linkat => (args[2] as i32, args[3]),
        _ => return None,
    };

    let raw = match read_proc_mem(notif.pid, path_addr, libc::PATH_MAX as usize) {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    Some(resolve_at_path(notif.pid, dirfd, &raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_basic() {
        assert_eq!(normalize_path(Path::new("/a/b/c")), PathBuf::from("/a/b/c"));
        assert_eq!(normalize_path(Path::new("/a/./b")), PathBuf::from("/a/b"));
        assert_eq!(
            normalize_path(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(normalize_path(Path::new("/")), PathBuf::from("/"));
        assert_eq!(
            normalize_path(Path::new("/a/b/../../c")),
            PathBuf::from("/c")
        );
    }

    #[test]
    fn test_normalize_relative() {
        assert_eq!(normalize_path(Path::new("a/b")), PathBuf::from("a/b"));
        assert_eq!(normalize_path(Path::new("./a")), PathBuf::from("a"));
    }
}
