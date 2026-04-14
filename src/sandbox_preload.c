// sandbox_preload.c — LD_PRELOAD shared library
// When loaded into a process, automatically installs seccomp filter
// and sends the notify fd to the supervisor.
//
// Build: gcc -shared -fPIC -o sandbox_preload.so sandbox_preload.c
// Usage: LD_PRELOAD=./sandbox_preload.so some_command

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define NOTIFY_SOCK_PATH "/run/whitelist-notify.sock"

static int install_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;

    return syscall(__NR_seccomp,
                   SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_NEW_LISTENER,
                   &prog);
}

static int send_notify_fd(int notify_fd) {
    const char *path = getenv("SANDBOX_SOCK_PATH");
    if (!path)
        path = NOTIFY_SOCK_PATH;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    char buf[1] = { 0 };
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

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = notify_fd;

    int ret = (sendmsg(sock, &msg, 0) < 0) ? -1 : 0;
    close(sock);
    return ret;
}

// Check if seccomp filter is already active (inherited from parent)
static int already_filtered(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        int mode;
        if (sscanf(line, "Seccomp:\t%d", &mode) == 1) {
            fclose(f);
            return mode == 2;  // 2 = SECCOMP_MODE_FILTER
        }
    }
    fclose(f);
    return 0;
}

// __attribute__((constructor)) runs before main()
__attribute__((constructor))
static void sandbox_init(void) {
    // Skip if filter already inherited from parent (fork case)
    if (already_filtered())
        return;

    int notify_fd = install_filter();
    if (notify_fd < 0) {
        fprintf(stderr, "[sandbox] failed to install seccomp filter: %s\n",
                strerror(errno));
        return;
    }

    if (send_notify_fd(notify_fd) < 0)
        fprintf(stderr, "[sandbox] WARNING: supervisor not reachable\n");

    close(notify_fd);
}
