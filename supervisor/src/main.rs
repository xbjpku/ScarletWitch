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
    Notification(SeccompNotif, RawFd),
    /// A notify fd was closed (child exited).
    NotifyFdClosed(RawFd),
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
                Err(_) => break,
            }
        }
    });
}

/// Spawn a dedicated blocking thread for recv_notif on a single fd.
/// The thread exits when the fd is closed (child exits). Each child
/// connection gets its own thread — no shared atomic, no races.
fn spawn_recv_thread_for_fd(
    fd: RawFd,
    tx: mpsc::UnboundedSender<Event>,
) {
    std::thread::spawn(move || {
        loop {
            match notif::recv_notif(fd) {
                Ok(n) => {
                    if tx.send(Event::Notification(n, fd)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    // fd closed or error — this thread is done
                    let _ = tx.send(Event::NotifyFdClosed(fd));
                    break;
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

    // Current active notify fd (only for dispatching responses)
    let mut notify_fd: RawFd = -1;

    // Event channel from blocking threads
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();

    // Spawn accept thread (one per session, long-lived)
    spawn_notify_accept_thread(notify_srv_fd, event_tx.clone());

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
            // Events from blocking threads
            Some(event) = event_rx.recv() => {
                match event {
                    Event::NewNotifyFd(fd) => {
                        notify_fd = fd;
                        eprintln!("[supervisor] received notify fd={}", fd);
                        // Spawn a dedicated recv thread for this fd
                        spawn_recv_thread_for_fd(fd, event_tx.clone());
                    }
                    Event::Notification(req, fd) => {
                        dispatch::handle_notification(fd, &req, &mut cow_table, &wl);
                    }
                    Event::NotifyFdClosed(fd) => {
                        eprintln!("[supervisor] notify fd={} closed", fd);
                        unsafe { libc::close(fd) };
                        if notify_fd == fd {
                            notify_fd = -1;
                        }
                    }
                }
            }

            // Ctrl command (async, request-response)
            result = ctrl_listener.accept() => {
                if let Ok((mut stream, _)) = result {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    if let Ok(n) = stream.read(&mut buf).await {
                        let input = String::from_utf8_lossy(&buf[..n]);
                        let cmd = input.trim();

                        if cmd.starts_with("RELOAD") {
                            match wl.reload(&conf_path) {
                                Ok(()) => {
                                    eprintln!("[supervisor] reloaded: write-allow={}, read-deny={}",
                                        wl.write_count(), wl.read_count());
                                    let _ = stream.write_all(b"{\"ok\":true}\n").await;
                                }
                                Err(e) => {
                                    eprintln!("[supervisor] reload failed: {}", e);
                                    let _ = stream.write_all(
                                        format!("{{\"ok\":false,\"error\":\"{}\"}}\n", e).as_bytes()
                                    ).await;
                                }
                            }
                        } else if cmd == "LIST_COW" {
                            let json = cow_table.to_json();
                            eprintln!("[supervisor] LIST_COW: {} entries", cow_table.entries().len());
                            let _ = stream.write_all(json.as_bytes()).await;
                            let _ = stream.write_all(b"\n").await;
                        } else if cmd.starts_with("COMMIT") {
                            // COMMIT\n["path1","path2"]
                            // or COMMIT ["path1","path2"] (single line)
                            let json_part = if let Some(rest) = cmd.strip_prefix("COMMIT") {
                                rest.trim()
                            } else { "" };

                            // Parse JSON array of paths
                            let paths = parse_json_string_array(json_part);
                            match cow_table.commit_paths(&paths) {
                                Ok(committed) => {
                                    eprintln!("[supervisor] COMMIT: {} paths committed", committed.len());
                                    let _ = stream.write_all(
                                        format!("{{\"ok\":true,\"committed\":{}}}\n", committed.len()).as_bytes()
                                    ).await;
                                }
                                Err(e) => {
                                    eprintln!("[supervisor] COMMIT failed: {}", e);
                                    let _ = stream.write_all(
                                        format!("{{\"ok\":false,\"error\":\"{}\"}}\n", e).as_bytes()
                                    ).await;
                                }
                            }
                        } else if cmd == "DISCARD" {
                            match cow_table.discard_all() {
                                Ok(()) => {
                                    let _ = stream.write_all(b"{\"ok\":true}\n").await;
                                }
                                Err(e) => {
                                    let _ = stream.write_all(
                                        format!("{{\"ok\":false,\"error\":\"{}\"}}\n", e).as_bytes()
                                    ).await;
                                }
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
    if notify_fd >= 0 {
        unsafe { libc::close(notify_fd) };
    }
    unsafe { libc::close(notify_srv_fd) };
    let _ = std::fs::remove_file(&ctrl_path);
    let _ = std::fs::remove_file(&notify_path);
}

/// Simple JSON string array parser: ["a","b","c"] → vec!["a","b","c"]
/// Handles escaped quotes. No external JSON dependency.
fn parse_json_string_array(input: &str) -> Vec<String> {
    let input = input.trim();
    if !input.starts_with('[') || !input.ends_with(']') {
        return Vec::new();
    }
    let inner = &input[1..input.len() - 1];
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => {
                if in_string {
                    result.push(current.clone());
                    current.clear();
                }
                in_string = !in_string;
            }
            _ if in_string => current.push(ch),
            _ => {} // skip commas, spaces outside strings
        }
    }
    result
}
