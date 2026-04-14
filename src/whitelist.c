#include "whitelist.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

ruleset_t  g_rulesets[2];
_Atomic int g_active = 0;

static int prefix_match(const rule_t *rules, int count, const char *path) {
    for (int i = 0; i < count; i++) {
        if (strncmp(path, rules[i].prefix, rules[i].prefix_len) == 0)
            return 1;
    }
    return 0;
}

static void add_rule(rule_t *rules, int *count, const char *prefix) {
    if (*count >= MAX_RULES)
        return;
    rule_t *r = &rules[*count];
    strncpy(r->prefix, prefix, PATH_LEN);
    r->prefix[PATH_LEN - 1] = '\0';
    r->prefix_len = strlen(r->prefix);
    (*count)++;
}

int load_rules(ruleset_t *rs, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    rs->write_count = 0;
    rs->read_count = 0;

    // 0 = no section, 1 = [write], 2 = [read]
    int section = 0;
    char line[PATH_LEN + 16];

    while (fgets(line, sizeof(line), f)) {
        // strip newline
        line[strcspn(line, "\n")] = '\0';

        if (line[0] == '#' || line[0] == '\0')
            continue;

        if (strcmp(line, "[write]") == 0) { section = 1; continue; }
        if (strcmp(line, "[read]") == 0)  { section = 2; continue; }

        if (section == 1)
            add_rule(rs->write_allow, &rs->write_count, line);
        else if (section == 2)
            add_rule(rs->read_deny, &rs->read_count, line);
    }

    fclose(f);
    return 0;
}

int check_path(const char *path, int open_flags) {
    int idx = atomic_load(&g_active);
    ruleset_t *rs = &g_rulesets[idx];

    int accmode = open_flags & O_ACCMODE;

    if (accmode == O_RDONLY) {
        // Read: blacklist — deny if matched, allow otherwise
        return prefix_match(rs->read_deny, rs->read_count, path) ? 0 : 1;
    }

    // Write (O_WRONLY / O_RDWR): whitelist — allow only if matched
    return prefix_match(rs->write_allow, rs->write_count, path) ? 1 : 0;
}
