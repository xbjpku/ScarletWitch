#ifndef COW_H
#define COW_H

#include <linux/limits.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <sys/types.h>

#define COW_MAX_ENTRIES 4096

typedef struct {
    char orig_path[PATH_MAX];
    char cow_path[PATH_MAX];
} cow_entry_t;

typedef struct {
    cow_entry_t entries[COW_MAX_ENTRIES];
    int count;
    char cow_dir[PATH_MAX];       // <session_dir>/cow_files
    char manifest_path[PATH_MAX]; // <session_dir>/cow_tree
} cow_table_t;

// Initialize COW table, create directories, load existing manifest.
int  cow_init(cow_table_t *tbl, const char *session_dir);

// Look up whether orig_path has a COW entry. Returns cow_path or NULL.
const char *cow_lookup(const cow_table_t *tbl, const char *orig_path);

// Perform COW: copy original file to cow_dir, add entry, write manifest.
// Returns 0 on success, -1 on error.
int  cow_materialize(cow_table_t *tbl, const char *orig_path, int open_flags, int mode);

// Open the COW copy and inject fd into target via SECCOMP_IOCTL_NOTIF_ADDFD.
// Returns remote fd number (>= 0) on success, -1 on error.
int  cow_inject_fd(int notify_fd, uint64_t req_id, const char *cow_path,
                   int open_flags, int mode);

// Resolve openat path to absolute form using /proc/<pid>/cwd or /proc/<pid>/fd/<dirfd>.
int  resolve_path(pid_t pid, int dirfd, const char *raw_path, char *out);

// Cleanup (no-op for static table).
void cow_destroy(cow_table_t *tbl);

#endif
