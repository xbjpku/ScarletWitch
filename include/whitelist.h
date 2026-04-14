#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdatomic.h>

#define MAX_RULES 1024
#define PATH_LEN  512

typedef struct {
    char prefix[PATH_LEN];
    int  prefix_len;
} rule_t;

typedef struct {
    rule_t write_allow[MAX_RULES];  // write whitelist: only these can be written
    int    write_count;

    rule_t read_deny[MAX_RULES];    // read blacklist: these cannot be read
    int    read_count;
} ruleset_t;

// Double-buffered rulesets with atomic index swap
extern ruleset_t  g_rulesets[2];
extern _Atomic int g_active;

// Load rules from config file into a ruleset. Returns 0 on success, -1 on error.
int  load_rules(ruleset_t *rs, const char *path);

// Check if a path can be opened with the given open flags.
// Returns 1 if permitted, 0 if denied.
int  check_path(const char *path, int open_flags);

#endif
