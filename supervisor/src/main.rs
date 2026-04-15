// supervisor — per-session seccomp notification supervisor (async tokio)
//
// Usage: supervisor --session <id> [--dir <base_dir>] [--from <whitelist>]
//
// Architecture:
//   - Notify socket (SCM_RIGHTS) accept handled in a blocking thread
//   - SECCOMP_IOCTL_NOTIF_RECV handled in a blocking thread
//   - Ctrl socket + signal handling via tokio async
//   - Notifications dispatched sequentially on the main async task

mod cow;
mod dispatch;
mod notif;
mod path;
mod whitelist;

use std::ffi::CString;
use std::io::{self, Read};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::mpsc;

use cow::CowTable;
use notif::SeccompNotif;
use whitelist::Whitelist;

const DEFAULT_BASE_DIR: &str = "/tmp/fastcode";

// ============================================================
// CLI argument parsing
// ============================================================

struct Config {
    session: String,
    basedir: PathBuf,
    from: Option<PathBuf>,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut session: Option<String> = None;
    let mut basedir = PathBuf::from(DEFAULT_BASE_DIR);
    let mut from: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--session" | "-s" => {
                i += 1;
                session = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--dir" | "-d" => {
                i += 1;
                if let Some(d) = args.get(i) {
                    basedir = PathBuf::from(d);
                }
            }
            "--from" | "-f" => {
                i += 1;
                if let Some(f) = args.get(i) {
                    from = Some(PathBuf::from(f));
                }
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: {} --session <id> [--from <whitelist>] [--dir <base_dir>]",
                    args[0]
                );
                eprintln!("\nPer-session supervisor process.");
                eprintln!("  --session, -s  Session ID (required)");
                eprintln!("  --from, -f     Source whitelist file to copy as initial config");
                eprintln!(
                    "  --dir, -d      Base directory (default: {})",
                    DEFAULT_BASE_DIR
                );
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    let session = session.unwrap_or_else(|| {
        eprintln!("Error: --session is required");
        std::process::exit(1);
    });

    Config {
        session,
        basedir,
        from,
    }
}

// ============================================================
// Raw Unix socket helpers (blocking, for SCM_RIGHTS)
// ============================================================

fn create_raw_unix_socket(path: &Path) -> io::Result<RawFd> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    use std::os::unix::io::IntoRawFd;
    Ok(listener.into_raw_fd())
}

/// Receive a notify fd from a child process via SCM_RIGHTS (blocking).
fn recv_notify_fd(server_fd: RawFd) -> io::Result<RawFd> {
    let client = unsafe { libc::accept(server_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if client < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    let n = unsafe { libc::recvmsg(client, &mut msg, 0) };
    unsafe { libc::close(client) };

    if n <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "recvmsg failed or empty",
        ));
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(io::ErrorKind::Other, "no control message"));
    }
    let cmsg_ref = unsafe { &*cmsg };
    if cmsg_ref.cmsg_type != libc::SCM_RIGHTS {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "expected SCM_RIGHTS",
        ));
    }

    let fd_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const i32;
    Ok(unsafe { *fd_ptr })
}

fn copy_file(src: &Path, dst: &Path) -> io::Result<()> {
    let mut input = std::fs::File::open(src)?;
    let mut output = std::fs::File::create(dst)?;
    let mut buf = [0u8; 4096];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        use std::io::Write;
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

// ============================================================
// Blocking threads → async channel bridge
// ============================================================

/// Messages from blocking threads to the async main loop.
enum Event {
    /// A new notify fd was received from a child via SCM_RIGHTS.
    NewNotifyFd(RawFd),
    /// A seccomp notification was received from the kernel.
    Notification(SeccompNotif),
    /// The notify fd was closed (child exited).
    NotifyFdClosed,
}

/// Spawn a thread that accepts connections on the notify socket and
/// receives fds via SCM_RIGHTS. Each received fd is sent as Event::NewNotifyFd.
fn spawn_notify_accept_thread(
    notify_srv_fd: RawFd,
    tx: mpsc::UnboundedSender<Event>,
) {
    std::thread::spawn(move || {
        loop {
            match recv_notify_fd(notify_srv_fd) {
                Ok(fd) => {
                    if tx.send(Event::NewNotifyFd(fd)).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    // Server socket closed or error
                    break;
                }
            }
        }
    });
}

/// Spawn a thread that calls SECCOMP_IOCTL_NOTIF_RECV in a loop.
/// Uses an AtomicI32 to track the current notify_fd (can be swapped).
fn spawn_notif_recv_thread(
    notify_fd: Arc<AtomicI32>,
    tx: mpsc::UnboundedSender<Event>,
) {
    std::thread::spawn(move || {
        loop {
            let fd = notify_fd.load(Ordering::Acquire);
            if fd < 0 {
                // No notify fd yet — sleep briefly and retry
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }

            match notif::recv_notif(fd) {
                Ok(n) => {
                    if tx.send(Event::Notification(n)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    // fd closed or error
                    let _ = tx.send(Event::NotifyFdClosed);
                    // Reset to -1 so we wait for a new fd
                    notify_fd.store(-1, Ordering::Release);
                }
            }
        }
    });
}

// ============================================================
// Main (async)
// ============================================================

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = parse_args();

    let _ = std::fs::create_dir_all(&config.basedir);

    let conf_path = config.basedir.join(format!("{}.conf", config.session));
    let ctrl_path = config
        .basedir
        .join(format!("{}.ctrl.sock", config.session));
    let notify_path = config
        .basedir
        .join(format!("{}.notify.sock", config.session));
    let log_path = config.basedir.join(format!("{}.log", config.session));
    let session_dir = config.basedir.join(&config.session);

    // Redirect stderr to log file
    if let Ok(cstr) = CString::new(log_path.to_string_lossy().as_bytes()) {
        let mode = CString::new("a").unwrap();
        let logf = unsafe { libc::fopen(cstr.as_ptr(), mode.as_ptr()) };
        if !logf.is_null() {
            unsafe {
                libc::dup2(libc::fileno(logf), libc::STDERR_FILENO);
                libc::fclose(logf);
                libc::setvbuf(
                    libc::fdopen(libc::STDERR_FILENO, b"a\0".as_ptr() as *const _),
                    std::ptr::null_mut(),
                    libc::_IONBF,
                    0,
                );
            }
        }
    }

    // Copy global whitelist
    if let Some(ref from) = config.from {
        match copy_file(from, &conf_path) {
            Ok(()) => eprintln!(
                "[supervisor] copied {} -> {}",
                from.display(),
                conf_path.display()
            ),
            Err(e) => eprintln!(
                "[supervisor] WARNING: failed to copy {}: {}",
                from.display(),
                e
            ),
        }
    }

    // Initialize COW
    let mut cow_table = match CowTable::init(&session_dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[supervisor] COW init failed: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("[supervisor] session: {}", config.session);
    eprintln!("[supervisor] whitelist: {}", conf_path.display());
    eprintln!("[supervisor] ctrl sock: {}", ctrl_path.display());
    eprintln!("[supervisor] notify sock: {}", notify_path.display());

    // Die when parent exits
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
    }

    // Load whitelist
    let mut wl = Whitelist::new();
    match wl.load(&conf_path) {
        Ok(()) => eprintln!(
            "[supervisor] loaded: write-allow={}, read-deny={}",
            wl.write_count(),
            wl.read_count()
        ),
        Err(_) => eprintln!("[supervisor] no whitelist yet, will reload later"),
    }

    // Create sockets
    let notify_srv_fd = create_raw_unix_socket(&notify_path).unwrap_or_else(|e| {
        eprintln!("[supervisor] notify socket: {}", e);
        std::process::exit(1);
    });

    let _ = std::fs::remove_file(&ctrl_path);
    let ctrl_std = std::os::unix::net::UnixListener::bind(&ctrl_path).unwrap_or_else(|e| {
        eprintln!("[supervisor] ctrl socket: {}", e);
        std::process::exit(1);
    });
    ctrl_std.set_nonblocking(true).ok();
    let ctrl_listener = UnixListener::from_std(ctrl_std).unwrap_or_else(|e| {
        eprintln!("[supervisor] ctrl tokio: {}", e);
        std::process::exit(1);
    });

    eprintln!(
        "[supervisor] waiting for notify fd on {}",
        notify_path.display()
    );

    // Shared notify_fd (AtomicI32 so recv thread can be swapped)
    let notify_fd = Arc::new(AtomicI32::new(-1));

    // Event channel from blocking threads
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();

    // Spawn blocking threads
    spawn_notify_accept_thread(notify_srv_fd, event_tx.clone());
    spawn_notif_recv_thread(Arc::clone(&notify_fd), event_tx);

    // Signal handlers
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();

    // ========================================
    // Async event loop
    // ========================================

    loop {
        tokio::select! {
            // Events from blocking threads (notify accept + seccomp recv)
            Some(event) = event_rx.recv() => {
                match event {
                    Event::NewNotifyFd(fd) => {
                        let old = notify_fd.swap(fd, Ordering::AcqRel);
                        if old >= 0 {
                            unsafe { libc::close(old) };
                        }
                        eprintln!("[supervisor] received notify fd={}", fd);
                    }
                    Event::Notification(req) => {
                        let fd = notify_fd.load(Ordering::Acquire);
                        if fd >= 0 {
                            dispatch::handle_notification(fd, &req, &mut cow_table, &wl);
                        }
                    }
                    Event::NotifyFdClosed => {
                        eprintln!("[supervisor] notify fd closed");
                    }
                }
            }

            // Ctrl command (async)
            result = ctrl_listener.accept() => {
                if let Ok((mut stream, _)) = result {
                    let mut buf = [0u8; 16];
                    use tokio::io::AsyncReadExt;
                    if let Ok(n) = stream.read(&mut buf).await {
                        let cmd = std::str::from_utf8(&buf[..n]).unwrap_or("");
                        if cmd.starts_with("RELOAD") {
                            match wl.reload(&conf_path) {
                                Ok(()) => eprintln!(
                                    "[supervisor] reloaded: write-allow={}, read-deny={}",
                                    wl.write_count(), wl.read_count()
                                ),
                                Err(e) => eprintln!("[supervisor] reload failed: {}", e),
                            }
                        }
                    }
                }
            }

            // Shutdown
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }

    // Cleanup
    eprintln!(
        "[supervisor] shutting down session {}",
        config.session
    );
    let fd = notify_fd.load(Ordering::Acquire);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    unsafe { libc::close(notify_srv_fd) };
    let _ = std::fs::remove_file(&ctrl_path);
    let _ = std::fs::remove_file(&notify_path);
}
