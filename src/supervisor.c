// supervisor.c — per-session supervisor process
// Usage: supervisor --session <session_id> [--dir <base_dir>]
//
// Paths derived from session_id:
//   whitelist:   <base_dir>/<session_id>.conf
//   ctrl socket: <base_dir>/<session_id>.ctrl.sock
//   notify socket: <base_dir>/<session_id>.notify.sock
//
// Default base_dir: /tmp/fastcode

#include "whitelist.h"
#include "cow.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <linux/limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdint.h>
#include <unistd.h>

#define DEFAULT_BASE_DIR "/tmp/fastcode"

static volatile sig_atomic_t g_running = 1;
static cow_table_t g_cow_table;

static void on_sigterm(int sig) {
    (void)sig;
    g_running = 0;
}

// Read a null-terminated string from target process memory
static int read_proc_mem(pid_t pid, uint64_t addr, char *buf, size_t len) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", pid);

    int fd = open(proc_path, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t n = pread(fd, buf, len - 1, addr);
    close(fd);

    if (n <= 0)
        return -1;

    buf[n] = '\0';
    return 0;
}

static void do_reload(const char *conf) {
    int next = 1 - atomic_load(&g_active);
    if (load_rules(&g_rulesets[next], conf) >= 0) {
        atomic_store(&g_active, next);
        fprintf(stderr, "[supervisor] reloaded: write-allow=%d, read-deny=%d\n",
                g_rulesets[next].write_count, g_rulesets[next].read_count);
    } else {
        fprintf(stderr, "[supervisor] reload failed\n");
    }
}

static int create_unix_socket(const char *path) {
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    listen(fd, 8);
    return fd;
}

// Receive a notify fd from a child process via SCM_RIGHTS
static int recv_notify_fd(int server_fd) {
    int client = accept(server_fd, NULL, NULL);
    if (client < 0)
        return -1;

    char buf[1];
    struct iovec iov = { .iov_base = buf, .iov_len = 1 };

    union {
        char   buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf.buf,
        .msg_controllen = sizeof(cmsg_buf.buf),
    };

    if (recvmsg(client, &msg, 0) <= 0) {
        close(client);
        return -1;
    }

    close(client);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
        return -1;

    return *(int *)CMSG_DATA(cmsg);
}

// Returns 0 on success, -1 if notify fd should be closed
static int handle_seccomp(int notify_fd) {
    struct seccomp_notif req = {};
    struct seccomp_notif_resp resp = {};

    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        if (errno == EINTR)
            return 0;
        fprintf(stderr, "[supervisor] NOTIF_RECV: %s (errno=%d), closing notify fd\n",
                strerror(errno), errno);
        return -1;
    }

    // Read raw path and resolve to absolute
    char raw_path[PATH_MAX] = {};
    read_proc_mem(req.pid, req.data.args[1], raw_path, PATH_MAX);
    int open_flags = (int)req.data.args[2];
    int mode = (open_flags & O_CREAT) ? (int)req.data.args[3] : 0644;
    int dirfd = (int)(int64_t)req.data.args[0];

    char path[PATH_MAX] = {};
    if (resolve_path(req.pid, dirfd, raw_path, path) < 0)
        strncpy(path, raw_path, PATH_MAX - 1);

    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) < 0) {
        fprintf(stderr, "[supervisor] request %llu invalidated\n",
                (unsigned long long)req.id);
        return 0;
    }

    const char *mode_str;
    int accmode = open_flags & O_ACCMODE;
    if (accmode == O_RDONLY)      mode_str = "R";
    else if (accmode == O_WRONLY) mode_str = "W";
    else                          mode_str = "RW";

    // Step 1: Check if path is already COW'd → redirect all access
    const char *cow_path = cow_lookup(&g_cow_table, path);
    if (cow_path) {
        fprintf(stderr, "[supervisor] COW-HIT openat(%s, %s) -> %s pid=%d\n",
                path, mode_str, cow_path, req.pid);
        if (cow_inject_fd(notify_fd, req.id, cow_path, open_flags, mode) >= 0)
            return 0;
        // Injection failed, fall through to deny
        goto deny;
    }

    // Step 2: Normal policy check
    if (check_path(path, open_flags)) {
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        resp.error = 0;
        fprintf(stderr, "[supervisor] ALLOW openat(%s, %s) pid=%d\n",
                path, mode_str, req.pid);
        goto send;
    }

    // Step 3: Denied — for write/RW, do COW instead of EACCES
    // cow_materialize will naturally fail for device files, FIFOs, etc.
    if (accmode != O_RDONLY) {
        fprintf(stderr, "[supervisor] COW-NEW openat(%s, %s) pid=%d\n",
                path, mode_str, req.pid);

        if (cow_materialize(&g_cow_table, path, open_flags, mode) < 0)
            goto deny;

        cow_path = cow_lookup(&g_cow_table, path);
        if (!cow_path)
            goto deny;

        if (cow_inject_fd(notify_fd, req.id, cow_path, open_flags, mode) >= 0)
            return 0;
        // Fall through to deny
    }

deny:
    resp.id = req.id;
    resp.flags = 0;
    resp.error = -EACCES;
    resp.val = 0;
    fprintf(stderr, "[supervisor] DENY  openat(%s, %s) pid=%d\n",
            path, mode_str, req.pid);

send:
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        fprintf(stderr, "[supervisor] NOTIF_SEND failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static void handle_ctrl(int ctrl_fd, const char *conf) {
    int client = accept(ctrl_fd, NULL, NULL);
    if (client < 0)
        return;

    char cmd[16] = {};
    recv(client, cmd, sizeof(cmd) - 1, 0);
    close(client);

    if (strncmp(cmd, "RELOAD", 6) == 0)
        do_reload(conf);
}

// Copy source file to destination
static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "r");
    if (!in)
        return -1;

    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return -1;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);

    fclose(in);
    fclose(out);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --session <id> [--from <whitelist>] [--dir <base_dir>]\n", prog);
    fprintf(stderr, "\nPer-session supervisor process.\n");
    fprintf(stderr, "  --session, -s  Session ID (required)\n");
    fprintf(stderr, "  --from, -f     Source whitelist file to copy as initial config\n");
    fprintf(stderr, "  --dir, -d      Base directory (default: %s)\n", DEFAULT_BASE_DIR);
    exit(1);
}

int main(int argc, char **argv) {
    const char *session = NULL;
    const char *basedir = DEFAULT_BASE_DIR;
    const char *from = NULL;

    static struct option opts[] = {
        { "session", required_argument, NULL, 's' },
        { "from",    required_argument, NULL, 'f' },
        { "dir",     required_argument, NULL, 'd' },
        { "help",    no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "s:f:d:h", opts, NULL)) != -1) {
        switch (ch) {
        case 's': session = optarg; break;
        case 'f': from = optarg;    break;
        case 'd': basedir = optarg; break;
        default:  usage(argv[0]);
        }
    }

    if (!session)
        usage(argv[0]);

    // Ensure base directory exists
    mkdir(basedir, 0700);

    // Redirect stderr to log file
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/%s.log", basedir, session);
    FILE *logf = fopen(log_path, "a");
    if (logf) {
        dup2(fileno(logf), STDERR_FILENO);
        fclose(logf);
        setbuf(stderr, NULL);  // unbuffered for real-time tailing
    }

    // Derive per-session paths
    char conf_path[PATH_MAX], ctrl_path[PATH_MAX], notify_path[PATH_MAX];
    snprintf(conf_path,   sizeof(conf_path),   "%s/%s.conf", basedir, session);
    snprintf(ctrl_path,   sizeof(ctrl_path),   "%s/%s.ctrl.sock", basedir, session);
    snprintf(notify_path, sizeof(notify_path), "%s/%s.notify.sock", basedir, session);

    // Copy global whitelist as initial per-session config
    if (from) {
        if (copy_file(from, conf_path) == 0)
            fprintf(stderr, "[supervisor] copied %s -> %s\n", from, conf_path);
        else
            fprintf(stderr, "[supervisor] WARNING: failed to copy %s: %s\n",
                    from, strerror(errno));
    }

    // Initialize COW subsystem
    char session_dir[PATH_MAX];
    snprintf(session_dir, sizeof(session_dir), "%s/%s", basedir, session);
    if (cow_init(&g_cow_table, session_dir) < 0)
        fprintf(stderr, "[supervisor] WARNING: COW init failed\n");

    fprintf(stderr, "[supervisor] session: %s\n", session);
    fprintf(stderr, "[supervisor] whitelist: %s\n", conf_path);
    fprintf(stderr, "[supervisor] ctrl sock: %s\n", ctrl_path);
    fprintf(stderr, "[supervisor] notify sock: %s\n", notify_path);

    // Die when parent (opencode) exits
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    // Graceful shutdown on SIGTERM/SIGINT
    signal(SIGTERM, on_sigterm);
    signal(SIGINT,  on_sigterm);

    // Initial load of rules
    if (load_rules(&g_rulesets[0], conf_path) >= 0)
        fprintf(stderr, "[supervisor] loaded: write-allow=%d, read-deny=%d\n",
                g_rulesets[0].write_count, g_rulesets[0].read_count);
    else
        fprintf(stderr, "[supervisor] no whitelist yet, will reload later\n");
    atomic_store(&g_active, 0);

    // Create sockets
    int ctrl_fd = create_unix_socket(ctrl_path);
    if (ctrl_fd < 0)
        return 1;

    int notify_srv = create_unix_socket(notify_path);
    if (notify_srv < 0)
        return 1;

    // Wait for first child to connect and send notify fd
    fprintf(stderr, "[supervisor] waiting for notify fd on %s\n", notify_path);

    // Poll: ctrl + notify_srv (+ notify_fd once connected)
    int notify_fd = -1;

    while (g_running) {
        struct pollfd fds[3];
        int nfds = 0;

        if (notify_fd >= 0)
            fds[nfds++] = (struct pollfd){ .fd = notify_fd, .events = POLLIN };

        fds[nfds++] = (struct pollfd){ .fd = ctrl_fd, .events = POLLIN };
        fds[nfds++] = (struct pollfd){ .fd = notify_srv, .events = POLLIN };

        int ret = poll(fds, nfds, -1);  // block until event
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (ret == 0)
            continue;

        for (int i = 0; i < nfds; i++) {
            if (!fds[i].revents)
                continue;

            // Handle POLLHUP/POLLERR on notify_fd first — the child may
            // have exited, leaving the fd with only POLLHUP (no POLLIN).
            // Without this, poll() returns immediately and we spin at 100% CPU.
            if (fds[i].fd == notify_fd &&
                (fds[i].revents & (POLLERR | POLLHUP))) {
                fprintf(stderr, "[supervisor] notify fd closed (revents=0x%x)\n",
                        fds[i].revents);
                close(notify_fd);
                notify_fd = -1;
                continue;
            }

            if (!(fds[i].revents & POLLIN))
                continue;

            if (fds[i].fd == notify_srv) {
                int fd = recv_notify_fd(notify_srv);
                if (fd >= 0) {
                    if (notify_fd >= 0)
                        close(notify_fd);
                    notify_fd = fd;
                    fprintf(stderr, "[supervisor] received notify fd=%d\n", fd);
                }
            } else if (fds[i].fd == ctrl_fd) {
                handle_ctrl(ctrl_fd, conf_path);
            } else if (fds[i].fd == notify_fd) {
                if (handle_seccomp(notify_fd) < 0) {
                    fprintf(stderr, "[supervisor] notify fd error, closing\n");
                    close(notify_fd);
                    notify_fd = -1;
                }
            }
        }
    }

    // Cleanup
    fprintf(stderr, "[supervisor] shutting down session %s\n", session);
    cow_destroy(&g_cow_table);
    if (notify_fd >= 0)
        close(notify_fd);
    close(ctrl_fd);
    close(notify_srv);
    unlink(ctrl_path);
    unlink(notify_path);

    return 0;
}
