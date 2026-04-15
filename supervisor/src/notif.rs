// Seccomp user notification ioctl wrappers.
//
// Kernel ABI structs and helpers for receiving notifications, sending
// responses, validating IDs, and injecting file descriptors.

use std::io;
use std::os::unix::io::RawFd;

// ============================================================
// Kernel ABI structs (must match kernel layout exactly)
// ============================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

// ============================================================
// ioctl command constants
// ============================================================

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0xc018_2103;

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

// ============================================================
// ioctl helpers
// ============================================================

/// Receive one seccomp notification (blocking).
pub fn recv_notif(fd: RawFd) -> io::Result<SeccompNotif> {
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif as *mut _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(notif)
    }
}

/// Send a CONTINUE response (let kernel execute the syscall normally).
pub fn respond_continue(fd: RawFd, id: u64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    send_resp(fd, &resp)
}

/// Send an ERRNO response (return -1 with given errno to the child).
pub fn respond_errno(fd: RawFd, id: u64, errno: i32) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    send_resp(fd, &resp)
}

/// Send a synthetic return value.
#[allow(dead_code)]
pub fn respond_value(fd: RawFd, id: u64, val: i64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val,
        error: 0,
        flags: 0,
    };
    send_resp(fd, &resp)
}

/// Check if a notification ID is still valid (TOCTOU guard).
pub fn id_valid(fd: RawFd, id: u64) -> io::Result<()> {
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Inject a file descriptor into the child and atomically respond.
///
/// Uses `SECCOMP_ADDFD_FLAG_SEND` for atomic inject+respond.
/// Falls back to two-step (ADDFD then manual SEND) on older kernels.
/// Returns the fd number assigned in the child process.
pub fn inject_fd_send(
    notify_fd: RawFd,
    req_id: u64,
    src_fd: RawFd,
    _open_flags: i32,
    _mode: i32,
) -> io::Result<i32> {
    // Try atomic ADDFD + FLAG_SEND first
    let addfd = SeccompNotifAddfd {
        id: req_id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    let ret = unsafe { libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd as *const _) };
    let saved_errno = io::Error::last_os_error();

    if ret >= 0 {
        return Ok(ret as i32);
    }

    // Fallback: EINVAL or ENOSYS means FLAG_SEND not supported
    if saved_errno.raw_os_error() == Some(libc::EINVAL)
        || saved_errno.raw_os_error() == Some(libc::ENOSYS)
    {
        let addfd2 = SeccompNotifAddfd {
            id: req_id,
            flags: 0,
            srcfd: src_fd as u32,
            newfd: 0,
            newfd_flags: 0,
        };
        let remote_fd =
            unsafe { libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd2 as *const _) };
        if remote_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Now send the response with the injected fd as return value
        let resp = SeccompNotifResp {
            id: req_id,
            val: remote_fd as i64,
            error: 0,
            flags: 0,
        };
        send_resp(notify_fd, &resp)?;
        return Ok(remote_fd as i32);
    }

    Err(saved_errno)
}

/// Raw ioctl to send a notification response.
fn send_resp(fd: RawFd, resp: &SeccompNotifResp) -> io::Result<()> {
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp as *const _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
