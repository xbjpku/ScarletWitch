#include "cow.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

// --- helpers ---

static int mkdirp(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    strncpy(tmp, path, PATH_MAX - 1);
    tmp[PATH_MAX - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    return mkdir(tmp, mode) < 0 && errno != EEXIST ? -1 : 0;
}

static int copy_file(const char *src, const char *dst) {
    // O_NONBLOCK prevents hanging on device files like /dev/tty
    int in_fd = open(src, O_RDONLY | O_NONBLOCK);
    if (in_fd < 0)
        return -1;

    // Reject non-regular files (devices, FIFOs, sockets)
    struct stat st;
    if (fstat(in_fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(in_fd);
        return -1;
    }

    // Regular file opened — clear O_NONBLOCK for normal reads
    fcntl(in_fd, F_SETFL, fcntl(in_fd, F_GETFL) & ~O_NONBLOCK);

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(out_fd, buf + written, n - written);
            if (w < 0) {
                close(in_fd);
                close(out_fd);
                return -1;
            }
            written += w;
        }
    }

    close(in_fd);
    close(out_fd);
    return n < 0 ? -1 : 0;
}

// Normalize path in-place: remove "." and resolve ".." components.
static void normalize_path(char *path) {
    char *comps[PATH_MAX / 2];
    int depth = 0;

    char *p = path;
    if (*p == '/')
        p++;

    char *start = p;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            if (strcmp(start, ".") == 0) {
                // skip
            } else if (strcmp(start, "..") == 0) {
                if (depth > 0)
                    depth--;
            } else if (start[0] != '\0') {
                comps[depth++] = start;
            }
            start = p + 1;
            p++;
        } else {
            p++;
        }
    }
    // last component
    if (strcmp(start, ".") == 0) {
        // skip
    } else if (strcmp(start, "..") == 0) {
        if (depth > 0)
            depth--;
    } else if (start[0] != '\0') {
        comps[depth++] = start;
    }

    // rebuild
    char result[PATH_MAX];
    result[0] = '/';
    result[1] = '\0';
    int pos = 1;
    for (int i = 0; i < depth; i++) {
        int len = strlen(comps[i]);
        if (pos + len + 1 >= PATH_MAX)
            break;
        memcpy(result + pos, comps[i], len);
        pos += len;
        if (i < depth - 1)
            result[pos++] = '/';
    }
    result[pos] = '\0';

    strcpy(path, result);
}

// --- manifest I/O ---

static void cow_save_manifest(cow_table_t *tbl) {
    FILE *f = fopen(tbl->manifest_path, "w");
    if (!f) {
        fprintf(stderr, "[cow] failed to write manifest: %s\n", strerror(errno));
        return;
    }

    // Build a sorted index of entries (sort pointers, not full structs)
    int indices[COW_MAX_ENTRIES];
    for (int i = 0; i < tbl->count; i++)
        indices[i] = i;

    // Simple insertion sort (count is small)
    for (int i = 1; i < tbl->count; i++) {
        int key = indices[i];
        int j = i - 1;
        while (j >= 0 && strcmp(tbl->entries[indices[j]].orig_path,
                                tbl->entries[key].orig_path) > 0) {
            indices[j + 1] = indices[j];
            j--;
        }
        indices[j + 1] = key;
    }

    // Build tree output
    // Track previous path components to avoid repeating directories
    // Max 64 components deep, max 256 chars per component
    char prev_parts[64][256];
    int prev_depth = 0;

    fprintf(f, "/\n");

    for (int i = 0; i < tbl->count; i++) {
        const char *path = tbl->entries[indices[i]].orig_path;
        if (path[0] != '/')
            continue;

        // Split path into components (skip leading /)
        char parts[64][256];
        int depth = 0;
        const char *p = path + 1;

        while (*p && depth < 64) {
            const char *slash = strchr(p, '/');
            if (slash) {
                int len = slash - p;
                if (len > 0 && len < 256) {
                    memcpy(parts[depth], p, len);
                    parts[depth][len] = '\0';
                    depth++;
                }
                p = slash + 1;
            } else {
                strncpy(parts[depth], p, 255);
                parts[depth][255] = '\0';
                depth++;
                break;
            }
        }

        if (depth == 0)
            continue;

        // Find common prefix with previous path
        int common = 0;
        while (common < prev_depth && common < depth - 1 &&
               strcmp(prev_parts[common], parts[common]) == 0) {
            common++;
        }

        // Print new directory components
        for (int d = common; d < depth - 1; d++) {
            for (int s = 0; s < (d + 1) * 2; s++)
                fputc(' ', f);
            fprintf(f, "%s/\n", parts[d]);
        }

        // Print file (leaf)
        for (int s = 0; s < depth * 2; s++)
            fputc(' ', f);
        fprintf(f, "%s\n", parts[depth - 1]);

        // Update prev
        memcpy(prev_parts, parts, sizeof(parts));
        prev_depth = depth;
    }

    fclose(f);
}

static void cow_load_manifest(cow_table_t *tbl) {
    FILE *f = fopen(tbl->manifest_path, "r");
    if (!f)
        return;

    // Directory stack: each level stores the directory name
    char dir_stack[128][256];
    int stack_depth = 0;

    char line[PATH_MAX + 64];
    while (fgets(line, sizeof(line), f)) {
        // Strip newline
        line[strcspn(line, "\n")] = '\0';

        // Skip comments and blank lines
        if (line[0] == '#' || line[0] == '\0')
            continue;

        // Root line
        if (strcmp(line, "/") == 0) {
            stack_depth = 0;
            continue;
        }

        // Count indent (2 spaces per level)
        int indent = 0;
        const char *p = line;
        while (*p == ' ') {
            indent++;
            p++;
        }
        int level = indent / 2;  // 0-based level within tree (level 0 = first indent)

        if (*p == '\0')
            continue;

        // Trim to this level
        if (level < stack_depth)
            stack_depth = level;

        // Check if directory (ends with /)
        int len = strlen(p);
        if (len > 0 && p[len - 1] == '/') {
            // Directory: push onto stack
            if (stack_depth < 128) {
                strncpy(dir_stack[stack_depth], p, len - 1);
                dir_stack[stack_depth][len - 1] = '\0';
                stack_depth++;
            }
        } else {
            // File: reconstruct full path
            if (tbl->count >= COW_MAX_ENTRIES)
                break;

            char orig[PATH_MAX] = "/";
            int pos = 1;
            for (int d = 0; d < stack_depth; d++) {
                int dlen = strlen(dir_stack[d]);
                if (pos + dlen + 1 < PATH_MAX) {
                    memcpy(orig + pos, dir_stack[d], dlen);
                    pos += dlen;
                    orig[pos++] = '/';
                }
            }
            int flen = strlen(p);
            if (pos + flen < PATH_MAX) {
                memcpy(orig + pos, p, flen);
                pos += flen;
            }
            orig[pos] = '\0';

            cow_entry_t *e = &tbl->entries[tbl->count];
            strncpy(e->orig_path, orig, PATH_MAX - 1);
            snprintf(e->cow_path, PATH_MAX, "%s%s", tbl->cow_dir, orig);
            tbl->count++;
        }
    }

    fclose(f);
    fprintf(stderr, "[cow] loaded %d entries from manifest\n", tbl->count);
}

// --- public API ---

int cow_init(cow_table_t *tbl, const char *session_dir) {
    memset(tbl, 0, sizeof(*tbl));

    snprintf(tbl->cow_dir, PATH_MAX, "%s/cow_files", session_dir);
    snprintf(tbl->manifest_path, PATH_MAX, "%s/cow_tree", session_dir);

    if (mkdir(session_dir, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "[cow] mkdir %s: %s\n", session_dir, strerror(errno));
        return -1;
    }
    if (mkdir(tbl->cow_dir, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "[cow] mkdir %s: %s\n", tbl->cow_dir, strerror(errno));
        return -1;
    }

    // Load existing manifest (if any, for session restart)
    cow_load_manifest(tbl);

    fprintf(stderr, "[cow] initialized: cow_dir=%s, entries=%d\n",
            tbl->cow_dir, tbl->count);
    return 0;
}

const char *cow_lookup(const cow_table_t *tbl, const char *orig_path) {
    for (int i = 0; i < tbl->count; i++) {
        if (strcmp(tbl->entries[i].orig_path, orig_path) == 0)
            return tbl->entries[i].cow_path;
    }
    return NULL;
}

int cow_materialize(cow_table_t *tbl, const char *orig_path, int open_flags, int mode) {
    // Already exists?
    if (cow_lookup(tbl, orig_path))
        return 0;

    if (tbl->count >= COW_MAX_ENTRIES) {
        fprintf(stderr, "[cow] table full (%d entries)\n", COW_MAX_ENTRIES);
        return -1;
    }

    // Build COW path
    char cow_path[PATH_MAX];
    snprintf(cow_path, PATH_MAX, "%s%s", tbl->cow_dir, orig_path);

    // Create parent directories
    char parent[PATH_MAX];
    strncpy(parent, cow_path, PATH_MAX - 1);
    parent[PATH_MAX - 1] = '\0';
    char *last_slash = strrchr(parent, '/');
    if (last_slash && last_slash != parent) {
        *last_slash = '\0';
        if (mkdirp(parent, 0755) < 0) {
            fprintf(stderr, "[cow] mkdirp %s: %s\n", parent, strerror(errno));
            return -1;
        }
    }

    // Copy original or create empty
    if (access(orig_path, F_OK) == 0) {
        if (copy_file(orig_path, cow_path) < 0) {
            fprintf(stderr, "[cow] copy %s -> %s: %s\n",
                    orig_path, cow_path, strerror(errno));
            return -1;
        }
        fprintf(stderr, "[cow] copied %s -> %s\n", orig_path, cow_path);
    } else if (open_flags & O_CREAT) {
        int fd = open(cow_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
        if (fd < 0) {
            fprintf(stderr, "[cow] create %s: %s\n", cow_path, strerror(errno));
            return -1;
        }
        close(fd);
        fprintf(stderr, "[cow] created empty %s\n", cow_path);
    } else {
        fprintf(stderr, "[cow] original %s does not exist and no O_CREAT\n", orig_path);
        return -1;
    }

    // Add to table
    cow_entry_t *e = &tbl->entries[tbl->count];
    strncpy(e->orig_path, orig_path, PATH_MAX - 1);
    strncpy(e->cow_path, cow_path, PATH_MAX - 1);
    tbl->count++;

    // Update manifest
    cow_save_manifest(tbl);

    return 0;
}

int cow_inject_fd(int notify_fd, uint64_t req_id, const char *cow_path,
                  int open_flags, int mode) {
    // Open COW file in supervisor process
    // Strip O_CREAT — the file already exists in cow_files
    // Preserve access mode, O_APPEND, O_TRUNC
    int sv_flags = (open_flags & (O_ACCMODE | O_APPEND | O_TRUNC));
    int sv_fd = open(cow_path, sv_flags, mode);
    if (sv_fd < 0) {
        fprintf(stderr, "[cow] open %s: %s\n", cow_path, strerror(errno));
        return -1;
    }

    // Validate notification is still alive
    uint64_t id = req_id;
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0) {
        fprintf(stderr, "[cow] notification %llu invalidated\n",
                (unsigned long long)req_id);
        close(sv_fd);
        return -1;
    }

    // Try atomic ADDFD + FLAG_SEND first
    struct seccomp_notif_addfd addfd;
    memset(&addfd, 0, sizeof(addfd));
    addfd.id       = req_id;
    addfd.flags    = SECCOMP_ADDFD_FLAG_SEND;
    addfd.srcfd    = sv_fd;

    int remote_fd = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    int saved_errno = errno;

    if (remote_fd < 0 && (saved_errno == EINVAL || saved_errno == ENOSYS)) {
        // FLAG_SEND not supported, fallback to two-step
        memset(&addfd, 0, sizeof(addfd));
        addfd.id    = req_id;
        addfd.srcfd = sv_fd;

        remote_fd = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
        if (remote_fd >= 0) {
            struct seccomp_notif_resp resp;
            memset(&resp, 0, sizeof(resp));
            resp.id  = req_id;
            resp.val = remote_fd;
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
                fprintf(stderr, "[cow] NOTIF_SEND after ADDFD: %s\n", strerror(errno));
                close(sv_fd);
                return -1;
            }
        }
    }

    close(sv_fd);

    if (remote_fd < 0) {
        fprintf(stderr, "[cow] ADDFD failed: %s\n", strerror(saved_errno));
        return -1;
    }

    fprintf(stderr, "[cow] injected fd=%d for %s\n", remote_fd, cow_path);
    return remote_fd;
}

int resolve_path(pid_t pid, int dirfd, const char *raw_path, char *out) {
    if (raw_path[0] == '/') {
        strncpy(out, raw_path, PATH_MAX - 1);
        out[PATH_MAX - 1] = '\0';
        normalize_path(out);
        return 0;
    }

    // Relative path — resolve base directory
    char base[PATH_MAX];

    if (dirfd == -100 /* AT_FDCWD */) {
        char proc_link[64];
        snprintf(proc_link, sizeof(proc_link), "/proc/%d/cwd", pid);
        ssize_t n = readlink(proc_link, base, sizeof(base) - 1);
        if (n < 0)
            return -1;
        base[n] = '\0';
    } else if (dirfd >= 0) {
        char proc_link[64];
        snprintf(proc_link, sizeof(proc_link), "/proc/%d/fd/%d", pid, dirfd);
        ssize_t n = readlink(proc_link, base, sizeof(base) - 1);
        if (n < 0)
            return -1;
        base[n] = '\0';
    } else {
        return -1;
    }

    snprintf(out, PATH_MAX, "%s/%s", base, raw_path);
    normalize_path(out);
    return 0;
}

void cow_destroy(cow_table_t *tbl) {
    memset(tbl, 0, sizeof(*tbl));
}
