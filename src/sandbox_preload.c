// sandbox_preload.c — LD_PRELOAD shared library (v2)
//
// When loaded into a process, applies:
//   1. Landlock filesystem ACL (defense-in-depth)
//   2. Seccomp BPF filter with:
//      - USER_NOTIF for file operations (openat + write-family)
//      - ERRNO(EPERM) for dangerous syscalls (mount, ptrace, bpf, ...)
//      - Arg-level filters (clone namespace flags, ioctl TIOCSTI, ...)
//      - Architecture check (x86_64 only)
//   3. Sends the seccomp notify fd to the supervisor via Unix socket
//
// Build: gcc -shared -fPIC -o sandbox_preload.so sandbox_preload.c
// Usage: LD_PRELOAD=./sandbox_preload.so some_command

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/limits.h>
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

// ============================================================
// Landlock (Phase 4)
// ============================================================

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

// Access bits (from landlock.h, may not be in older headers)
#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE          (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE       (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE        (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR         (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR       (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE      (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR        (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR         (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG         (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK        (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO        (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK       (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM         (1ULL << 12)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER            (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE         (1ULL << 14)
#endif

static int add_path_rule(int ruleset_fd, const char *path, __u64 access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;  // path doesn't exist, skip

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int ret = syscall(__NR_landlock_add_rule, ruleset_fd,
                      LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    return ret;
}

static int apply_landlock(void) {
    // Derive config path from SANDBOX_SOCK_PATH
    // SANDBOX_SOCK_PATH = /tmp/fastcode/SESSION.notify.sock
    // conf_path         = /tmp/fastcode/SESSION.conf
    const char *sock_path = getenv("SANDBOX_SOCK_PATH");
    if (!sock_path) return 0;  // no sandbox config, skip Landlock

    char conf_path[PATH_MAX];
    strncpy(conf_path, sock_path, PATH_MAX - 1);
    conf_path[PATH_MAX - 1] = '\0';

    // Strip ".notify.sock" and append ".conf"
    char *suffix = strstr(conf_path, ".notify.sock");
    if (!suffix) return 0;
    strcpy(suffix, ".conf");

    // Query Landlock ABI version
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        // Landlock not available — degrade gracefully
        return 0;
    }

    // Build handled_access_fs bitmask (ABI-version-aware)
    __u64 handled = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR   | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE| LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR   | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK  | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;

    __u64 read_access  = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    struct landlock_ruleset_attr attr = { .handled_access_fs = handled };
    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset_fd < 0) return -1;

    // Standard read paths (always allowed)
    const char *read_paths[] = {
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/proc", "/dev", "/sys", "/run",
        NULL
    };
    for (int i = 0; read_paths[i]; i++)
        add_path_rule(ruleset_fd, read_paths[i], read_access);

    // Parse config file: [write] paths get full access
    FILE *f = fopen(conf_path, "r");
    if (f) {
        int section = 0;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            if (line[0] == '#' || line[0] == '\0') continue;
            if (strcmp(line, "[write]") == 0) { section = 1; continue; }
            if (strcmp(line, "[read]") == 0)  { section = 2; continue; }

            if (section == 1) {
                // Write paths get full access (read + write + create + delete)
                add_path_rule(ruleset_fd, line, handled);
            }
            // Read-deny paths are NOT added to Landlock (handled by supervisor)
        }
        fclose(f);
    }

    // Also allow access to the base directory (for sockets, logs, COW)
    char basedir[PATH_MAX];
    strncpy(basedir, sock_path, PATH_MAX - 1);
    basedir[PATH_MAX - 1] = '\0';
    char *last_slash = strrchr(basedir, '/');
    if (last_slash) {
        *last_slash = '\0';
        add_path_rule(ruleset_fd, basedir, handled);
    }

    // Allow /tmp for general temp file usage
    add_path_rule(ruleset_fd, "/tmp", handled);

    // Allow /dev read+write (for /dev/null, /dev/tty, /dev/urandom, etc.)
    add_path_rule(ruleset_fd, "/dev", handled);

    // Allow read access to the preload .so itself (for child process LD_PRELOAD)
    const char *preload_path = getenv("LD_PRELOAD");
    if (preload_path) {
        // LD_PRELOAD may contain multiple entries separated by colons/spaces
        char preload_copy[PATH_MAX];
        strncpy(preload_copy, preload_path, PATH_MAX - 1);
        preload_copy[PATH_MAX - 1] = '\0';
        char *tok = strtok(preload_copy, ": ");
        while (tok) {
            // Add the directory containing the .so for read access
            char dir[PATH_MAX];
            strncpy(dir, tok, PATH_MAX - 1);
            dir[PATH_MAX - 1] = '\0';
            char *ds = strrchr(dir, '/');
            if (ds) {
                *ds = '\0';
                add_path_rule(ruleset_fd, dir, read_access);
            }
            tok = strtok(NULL, ": ");
        }
    }

    // Allow read access to the current working directory
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)))
        add_path_rule(ruleset_fd, cwd, read_access);

    // Enforce (irreversible)
    // PR_SET_NO_NEW_PRIVS is set later in install_filter(), but Landlock also
    // requires it. Calling it here is safe (idempotent).
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int ret = syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
    close(ruleset_fd);

    if (ret < 0) {
        fprintf(stderr, "[sandbox] landlock_restrict_self: %s\n", strerror(errno));
        return -1;
    }

    // Landlock log goes to child stderr, not supervisor log — keep quiet
    // unless SANDBOX_DEBUG is set.
    if (getenv("SANDBOX_DEBUG"))
        fprintf(stderr, "[sandbox] Landlock applied (ABI v%d)\n", abi);
    return 0;
}

// ============================================================
// Seccomp BPF filter (Phases 2+3)
// ============================================================

// Arg-level filter offsets
#define OFFSET_NR       offsetof(struct seccomp_data, nr)
#define OFFSET_ARCH     offsetof(struct seccomp_data, arch)
#define OFFSET_ARGS0_LO (offsetof(struct seccomp_data, args) + 0*8)
#define OFFSET_ARGS1_LO (offsetof(struct seccomp_data, args) + 1*8)

#define AUDIT_ARCH_X86_64 0xC000003E

// Clone namespace flags to block
#define CLONE_NS_FLAGS (0x00020000 /* CLONE_NEWNS */     \
                      | 0x02000000 /* CLONE_NEWCGROUP */  \
                      | 0x04000000 /* CLONE_NEWUTS */     \
                      | 0x08000000 /* CLONE_NEWIPC */     \
                      | 0x10000000 /* CLONE_NEWUSER */    \
                      | 0x20000000 /* CLONE_NEWPID */     \
                      | 0x40000000 /* CLONE_NEWNET */)

#define TIOCSTI  0x5412
#define TIOCLINUX 0x541C

// prctl ops to block
#define PR_SET_DUMPABLE     4
#define PR_SET_SECUREBITS  28
#define PR_SET_PTRACER      0x59616d61

// Helper: syscall numbers for notify and deny lists
static const int notif_syscalls[] = {
    __NR_openat,                    // file open (COW, whitelist)
    // Modern *at variants
    __NR_unlinkat,                  // delete file/dir
    __NR_mkdirat,                   // create directory
    __NR_symlinkat,                 // create symlink
    __NR_linkat,                    // create hard link
    __NR_fchmodat,                  // change permissions
    __NR_fchownat,                  // change ownership
    __NR_truncate,                  // truncate file
#ifdef __NR_renameat2
    __NR_renameat2,                 // rename
#endif
    // Legacy variants (coreutils often uses these instead of *at)
    __NR_mkdir,                     // legacy mkdir(path, mode)
    __NR_unlink,                    // legacy unlink(path)
    __NR_rmdir,                     // legacy rmdir(path)
    __NR_rename,                    // legacy rename(old, new)
    __NR_symlink,                   // legacy symlink(target, linkpath)
    __NR_link,                      // legacy link(old, new)
    __NR_chmod,                     // legacy chmod(path, mode)
    __NR_chown,                     // legacy chown(path, uid, gid)
    __NR_lchown,                    // legacy lchown(path, uid, gid)
};
#define N_NOTIF (sizeof(notif_syscalls) / sizeof(notif_syscalls[0]))

static const int deny_syscalls[] = {
    __NR_mount,
    __NR_umount2,
    __NR_pivot_root,
    __NR_swapon,
    __NR_swapoff,
    __NR_reboot,
    __NR_sethostname,
    __NR_setdomainname,
    __NR_kexec_load,
    __NR_init_module,
    __NR_finit_module,
    __NR_delete_module,
    __NR_unshare,
    __NR_setns,
    __NR_perf_event_open,
    __NR_bpf,
    __NR_userfaultfd,
    __NR_keyctl,
    __NR_add_key,
    __NR_request_key,
    __NR_ptrace,
    __NR_process_vm_readv,
    __NR_process_vm_writev,
#ifdef __NR_io_uring_setup
    __NR_io_uring_setup,
    __NR_io_uring_enter,
    __NR_io_uring_register,
#endif
};
#define N_DENY (sizeof(deny_syscalls) / sizeof(deny_syscalls[0]))

static int install_filter(void) {
    // Layout:
    //   [arch check: 2]
    //   [arg filters: variable]
    //   [LD NR: 1]
    //   [notif JEQs: N_NOTIF]
    //   [deny JEQs: N_DENY]
    //   [RET ALLOW]
    //   [RET USER_NOTIF]
    //   [RET ERRNO(EPERM)]
    //   [RET KILL_PROCESS]

    // --- Arg-level filter blocks ---
    // clone: block namespace flags (5 insns)
    // ioctl: block TIOCSTI + TIOCLINUX (7 insns)
    // prctl: block dangerous ops (9 insns)
    // socket: block AF_NETLINK (5 insns)
    #define ARG_BLOCK_SIZE (5 + 7 + 9 + 5)

    const unsigned int total = 2 + ARG_BLOCK_SIZE + 1 + N_NOTIF + N_DENY + 4;
    const unsigned int ret_notif_idx   = total - 3;
    const unsigned int ret_errno_idx   = total - 2;
    const unsigned int ret_kill_idx    = total - 1;

    struct sock_filter filter[256];  // max 256 instructions (well under 4096 limit)
    unsigned int n = 0;

    // ---- 1. Architecture check ----
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                      AUDIT_ARCH_X86_64, 0, ret_kill_idx - 2);

    // ---- 2. Arg-level filters ----

    // --- clone: block namespace flags ---
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NS_FLAGS, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);

    // --- ioctl: block TIOCSTI + TIOCLINUX ---
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS1_LO);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);

    // --- prctl: block dangerous ops ---
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 7);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_DUMPABLE, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECUREBITS, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_PTRACER, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);

    // --- socket: block AF_NETLINK ---
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 3);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS0_LO);
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 16 /*AF_NETLINK*/, 0, 1);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);

    // ---- 3. Load syscall number ----
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);

    // ---- 4. NOTIF JEQ instructions ----
    for (unsigned int i = 0; i < N_NOTIF; i++) {
        unsigned int pos = n;
        unsigned int jt = ret_notif_idx - (pos + 1);
        filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          notif_syscalls[i], jt, 0);
    }

    // ---- 5. DENY JEQ instructions ----
    for (unsigned int i = 0; i < N_DENY; i++) {
        unsigned int pos = n;
        unsigned int jt = ret_errno_idx - (pos + 1);
        filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                          deny_syscalls[i], jt, 0);
    }

    // ---- 6. Return instructions ----
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    struct sock_fprog prog = {
        .len = n,
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;

    return syscall(__NR_seccomp,
                   SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_NEW_LISTENER,
                   &prog);
}

// ============================================================
// Notify fd transmission via SCM_RIGHTS
// ============================================================

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

// ============================================================
// Nesting detection
// ============================================================

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

// ============================================================
// Constructor — runs before main()
// ============================================================

__attribute__((constructor))
static void sandbox_init(void) {
    // Skip if filter already inherited from parent (fork case)
    if (already_filtered())
        return;

    // 1. Apply Landlock (defense-in-depth, doesn't need supervisor)
    if (apply_landlock() < 0)
        if (getenv("SANDBOX_DEBUG"))
            fprintf(stderr, "[sandbox] WARNING: Landlock not applied\n");

    // 2. Install expanded seccomp filter
    int notify_fd = install_filter();
    if (notify_fd < 0) {
        fprintf(stderr, "[sandbox] failed to install seccomp filter: %s\n",
                strerror(errno));
        return;
    }

    // 3. Send notify fd to supervisor
    if (send_notify_fd(notify_fd) < 0)
        fprintf(stderr, "[sandbox] WARNING: supervisor not reachable\n");

    close(notify_fd);
}
