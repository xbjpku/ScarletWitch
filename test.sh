#!/bin/bash
# Long-range COW tests: multiple commands in one session, testing
# per-command snapshots, multi-file writes, re-writes, reads, and edge cases.
#
# Usage: ./test.sh
# Runs all tests, prints PASS/FAIL for each.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SESSION="test_$$"
BASE="/tmp/fastcode"
CONF="$DIR/whitelist.conf"
WORKSPACE="/mnt/user-ssd/xiaobangjun/pku_workspace"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0

cleanup() {
    kill $SV_PID 2>/dev/null
    wait $SV_PID 2>/dev/null
    rm -rf "$BASE/$SESSION"* 2>/dev/null
    # Restore original test files
    echo "original_a" > "$WORKSPACE/test_cow.txt"
    echo "original_b" > "$WORKSPACE/test_cow2.txt"
    rm -f "$WORKSPACE/test_cow3.txt"
}

start_supervisor() {
    mkdir -p "$BASE"
    rm -f "$BASE/$SESSION".*
    "$DIR/build/supervisor" --session "$SESSION" --dir "$BASE" --from "$CONF" &
    SV_PID=$!
    sleep 0.3
    if ! kill -0 $SV_PID 2>/dev/null; then
        echo "ERROR: supervisor failed to start"
        exit 1
    fi
}

# Run a command under the sandbox with a unique SCARLET_CMD_ID
CMD_COUNTER=0
run_cmd() {
    CMD_COUNTER=$((CMD_COUNTER + 1))

    SANDBOX_SOCK_PATH="$BASE/$SESSION.notify.sock" \
    LD_PRELOAD="$DIR/build/sandbox_preload.so" \
    SCARLET_CMD_ID="test_cmd_$CMD_COUNTER" \
        bash -c "$1" 2>/dev/null
}

# Query LIST_COW and return JSON.  Usage: list_cow [strict|medium|loose]
list_cow() {
    local level="${1:-medium}"
    node -e "
var c=require('net').createConnection('$BASE/$SESSION.ctrl.sock',function(){c.write('LIST_COW $level\n')});
var d='';c.on('data',function(k){d+=k});c.on('end',function(){process.stdout.write(d);process.exit(0)});
c.on('error',function(e){process.exit(1)});setTimeout(function(){process.stdout.write(d);process.exit(0)},1000);
    " 2>/dev/null
}

# Send COMMIT_GEN
commit_gen() {
    node -e "
var c=require('net').createConnection('$BASE/$SESSION.ctrl.sock',function(){c.write('COMMIT_GEN $1\n')});
var d='';c.on('data',function(k){d+=k});c.on('end',function(){process.stdout.write(d);process.exit(0)});
c.on('error',function(e){process.exit(1)});setTimeout(function(){process.stdout.write(d);process.exit(0)},1000);
    " 2>/dev/null
}

# Send DISCARD
discard_all() {
    node -e "
var c=require('net').createConnection('$BASE/$SESSION.ctrl.sock',function(){c.write('DISCARD\n')});
var d='';c.on('data',function(k){d+=k});c.on('end',function(){process.stdout.write(d);process.exit(0)});
c.on('error',function(e){process.exit(1)});setTimeout(function(){process.stdout.write(d);process.exit(0)},1000);
    " 2>/dev/null
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        echo "    expected to contain: $needle"
        echo "    actual: $haystack"
        FAIL=$((FAIL + 1))
    fi
}

# Setup test files
echo "original_a" > "$WORKSPACE/test_cow.txt"
echo "original_b" > "$WORKSPACE/test_cow2.txt"
rm -f "$WORKSPACE/test_cow3.txt"

########################################################################
echo -e "\n${CYAN}=== Test 1: Basic per-command snapshots ===${NC}"
echo "  4 alternating writes to 2 files, expect 4 entries"
########################################################################
start_supervisor

run_cmd "echo version1_a > $WORKSPACE/test_cow.txt"
run_cmd "echo version1_b > $WORKSPACE/test_cow2.txt"
run_cmd "echo version2_a > $WORKSPACE/test_cow.txt"
run_cmd "echo version2_b > $WORKSPACE/test_cow2.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "4 cow entries total" "4" "$COUNT"

# Check that versioned files exist
assert_eq "test_cow.v0 exists" "true" "$([ -f $BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0 ] && echo true || echo false)"
assert_eq "test_cow2.v0 exists" "true" "$([ -f $BASE/$SESSION/cow_files$WORKSPACE/test_cow2.v0 ] && echo true || echo false)"

# Check content of versions
V0_A=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0")
LATEST_A=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "v0 of test_cow has version1_a" "version1_a" "$V0_A"
assert_eq "latest test_cow has version2_a" "version2_a" "$LATEST_A"

# Original file on disk should be unchanged
ORIG_A=$(cat "$WORKSPACE/test_cow.txt")
assert_eq "original file unchanged" "original_a" "$ORIG_A"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 2: COMMIT_GEN partial commit ===${NC}"
echo "  Commit first 2 commands, verify remaining 2 stay"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
echo "original_b" > "$WORKSPACE/test_cow2.txt"
start_supervisor

run_cmd "echo commit_v1_a > $WORKSPACE/test_cow.txt"    # gen 1
run_cmd "echo commit_v1_b > $WORKSPACE/test_cow2.txt"   # gen 2
run_cmd "echo commit_v2_a > $WORKSPACE/test_cow.txt"    # gen 3
run_cmd "echo commit_v2_b > $WORKSPACE/test_cow2.txt"   # gen 4

# Commit up to gen 2 (first 2 commands)
COMMIT_RESULT=$(commit_gen 2)
assert_contains "commit gen 2 ok" '"ok":true' "$COMMIT_RESULT"

# Check: files on disk should have gen 1/2 content
DISK_A=$(cat "$WORKSPACE/test_cow.txt")
DISK_B=$(cat "$WORKSPACE/test_cow2.txt")
assert_eq "test_cow committed to gen1 value" "commit_v1_a" "$DISK_A"
assert_eq "test_cow2 committed to gen2 value" "commit_v1_b" "$DISK_B"

# Remaining entries should be gen 3 and 4
COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries remaining after partial commit" "2" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 3: Same file written 3 times ===${NC}"
echo "  Single file written by 3 commands, expect 3 entries + 2 versioned files"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo first > $WORKSPACE/test_cow.txt"
run_cmd "echo second > $WORKSPACE/test_cow.txt"
run_cmd "echo third > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "3 entries for same file" "3" "$COUNT"

V0=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0")
V1=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v1")
LATEST=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "v0 = first" "first" "$V0"
assert_eq "v1 = second" "second" "$V1"
assert_eq "latest = third" "third" "$LATEST"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 4: Mixed read + write (read should not create entry) ===${NC}"
echo "  Write then read same file, expect only 1 entry"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo written > $WORKSPACE/test_cow.txt"
run_cmd "cat $WORKSPACE/test_cow.txt > /dev/null"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "only 1 entry (read doesn't create new)" "1" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 5: Write to new file (O_CREAT) ===${NC}"
echo "  Create a new file via redirect, expect 1 entry"
########################################################################
rm -f "$WORKSPACE/test_cow3.txt"
start_supervisor

run_cmd "echo new_file > $WORKSPACE/test_cow3.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry for new file" "1" "$COUNT"

# Original should not exist on disk (cow intercepted)
assert_eq "new file not on real disk" "false" "$([ -f $WORKSPACE/test_cow3.txt ] && echo true || echo false)"

# Commit and verify
commit_gen 999
assert_eq "new file on disk after commit" "new_file" "$(cat $WORKSPACE/test_cow3.txt)"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 6: DISCARD drops everything ===${NC}"
echo "  Write files then discard, original should be unchanged"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo should_be_gone > $WORKSPACE/test_cow.txt"
discard_all

DISK_A=$(cat "$WORKSPACE/test_cow.txt")
assert_eq "original unchanged after discard" "original_a" "$DISK_A"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "0 entries after discard" "0" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 7: Rapid writes same generation (no snapshot within same cmd) ===${NC}"
echo "  Multiple writes in one command, expect 1 entry (same generation)"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo first > $WORKSPACE/test_cow.txt && echo second > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry for multiple writes in same cmd" "1" "$COUNT"

LATEST=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "latest has last write" "second" "$LATEST"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 8: Multi-file single command ===${NC}"
echo "  One command writes 2 files, expect 2 entries in same generation"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
echo "original_b" > "$WORKSPACE/test_cow2.txt"
start_supervisor

run_cmd "echo multi_a > $WORKSPACE/test_cow.txt && echo multi_b > $WORKSPACE/test_cow2.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries for multi-file cmd" "2" "$COUNT"

# Both should have same generation
GENS=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries;console.log([...new Set(e.map(x=>x.generation))].join(','))})")
assert_eq "same generation for both files" "1" "$GENS"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 9: mkdir (COW directory creation) ===${NC}"
echo "  mkdir a new directory, expect 1 entry"
########################################################################
start_supervisor

run_cmd "mkdir $WORKSPACE/test_cow_dir"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry for mkdir" "1" "$COUNT"

# Dir should NOT exist on real disk
assert_eq "dir not on real disk" "false" "$([ -d $WORKSPACE/test_cow_dir ] && echo true || echo false)"

# But should exist in cow layer
assert_eq "dir in cow layer" "true" "$([ -d $BASE/$SESSION/cow_files$WORKSPACE/test_cow_dir ] && echo true || echo false)"

# Commit and verify
commit_gen 999
assert_eq "dir on disk after commit" "true" "$([ -d $WORKSPACE/test_cow_dir ] && echo true || echo false)"
rmdir "$WORKSPACE/test_cow_dir" 2>/dev/null

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 10: rename (COW file rename) ===${NC}"
echo "  Write a file then rename it, expect 2 entries"
########################################################################
echo "rename_me" > "$WORKSPACE/test_cow.txt"
rm -f "$WORKSPACE/test_cow_renamed.txt"
start_supervisor

run_cmd "echo content > $WORKSPACE/test_cow.txt"
run_cmd "mv $WORKSPACE/test_cow.txt $WORKSPACE/test_cow_renamed.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
# openat creates 1 entry for test_cow.txt, rename replaces it with test_cow_renamed.txt
# So we expect 1 entry (rename removes source entry and adds dest)
assert_eq "1 entry after write+rename" "1" "$COUNT"

# Check the entry is for the renamed path
HAS_RENAMED=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries;console.log(e.some(x=>x.orig_path.includes('test_cow_renamed')))})")
assert_eq "entry is for renamed path" "true" "$HAS_RENAMED"

# Original should still be on disk (cow intercepted the rename)
assert_eq "original still on disk" "true" "$([ -f $WORKSPACE/test_cow.txt ] && echo true || echo false)"
assert_eq "renamed NOT on disk yet" "false" "$([ -f $WORKSPACE/test_cow_renamed.txt ] && echo true || echo false)"

# Commit and verify
commit_gen 999
assert_eq "renamed file on disk after commit" "true" "$([ -f $WORKSPACE/test_cow_renamed.txt ] && echo true || echo false)"
CONTENT=$(cat "$WORKSPACE/test_cow_renamed.txt")
assert_eq "renamed file has correct content" "content" "$CONTENT"

rm -f "$WORKSPACE/test_cow_renamed.txt"
echo "rename_me" > "$WORKSPACE/test_cow.txt"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 11: chmod (COW permission change) ===${NC}"
echo "  Write a file then chmod it"
########################################################################
echo "chmod_test" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo data > $WORKSPACE/test_cow.txt"
run_cmd "chmod 755 $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
# chmod now triggers snapshot_for_reopen (via ensure_materialized), creating a new entry
assert_eq "2 entries (write gen1 + chmod gen2)" "2" "$COUNT"

# Check that cow file has 755 perms
COW_PERMS=$(stat -c '%a' "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt" 2>/dev/null)
assert_eq "cow file has 755 perms" "755" "$COW_PERMS"

# Original should still have old perms
ORIG_PERMS=$(stat -c '%a' "$WORKSPACE/test_cow.txt" 2>/dev/null)
assert_eq "original perms unchanged" "644" "$ORIG_PERMS"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 12: symlink (COW symlink creation) ===${NC}"
echo "  Create a symlink, expect 1 entry"
########################################################################
rm -f "$WORKSPACE/test_cow_link"
echo "link_target" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "ln -s $WORKSPACE/test_cow.txt $WORKSPACE/test_cow_link"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry for symlink" "1" "$COUNT"

# Symlink should NOT exist on real disk
assert_eq "symlink not on real disk" "false" "$([ -L $WORKSPACE/test_cow_link ] && echo true || echo false)"

# But should exist in cow layer
assert_eq "symlink in cow layer" "true" "$([ -L $BASE/$SESSION/cow_files$WORKSPACE/test_cow_link ] && echo true || echo false)"

# Commit and verify
commit_gen 999
assert_eq "symlink on disk after commit" "true" "$([ -L $WORKSPACE/test_cow_link ] && echo true || echo false)"
LINK_TARGET=$(readlink "$WORKSPACE/test_cow_link")
assert_eq "symlink points to correct target" "$WORKSPACE/test_cow.txt" "$LINK_TARGET"

rm -f "$WORKSPACE/test_cow_link"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 13: truncate (COW file truncation) ===${NC}"
echo "  Write a file then truncate it"
########################################################################
echo "truncate_this_long_content" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo some_data > $WORKSPACE/test_cow.txt"
run_cmd "truncate -s 0 $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries (write + truncate)" "2" "$COUNT"

# Cow file should be empty (truncated to 0)
COW_SIZE=$(stat -c '%s' "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt" 2>/dev/null)
assert_eq "cow file is 0 bytes" "0" "$COW_SIZE"

# Original should still have content
ORIG_SIZE=$(stat -c '%s' "$WORKSPACE/test_cow.txt" 2>/dev/null)
assert_eq "original still has content" "true" "$([ $ORIG_SIZE -gt 0 ] && echo true || echo false)"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 14: Rename then write to new name ===${NC}"
echo "  Write, rename, then write to renamed file in 3 commands"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
rm -f "$WORKSPACE/test_cow_moved.txt"
start_supervisor

run_cmd "echo step1 > $WORKSPACE/test_cow.txt"          # gen 1: write
run_cmd "mv $WORKSPACE/test_cow.txt $WORKSPACE/test_cow_moved.txt"  # gen 2: rename
run_cmd "echo step3 > $WORKSPACE/test_cow_moved.txt"     # gen 3: write to renamed

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
# rename removes test_cow.txt entry, adds test_cow_moved.txt
# write to renamed creates snapshot + new entry for test_cow_moved.txt
assert_eq "2 entries (rename dest + write to renamed)" "2" "$COUNT"

# Commit all and verify
commit_gen 999
CONTENT=$(cat "$WORKSPACE/test_cow_moved.txt")
assert_eq "renamed+written file has final content" "step3" "$CONTENT"

rm -f "$WORKSPACE/test_cow_moved.txt"
echo "original" > "$WORKSPACE/test_cow.txt"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 15: append mode (>>) ===${NC}"
echo "  Write then append, check both versions"
########################################################################
echo "base" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo line1 > $WORKSPACE/test_cow.txt"
run_cmd "echo line2 >> $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries (write + append)" "2" "$COUNT"

# v0 should have "line1", latest should have "line1\nline2"
V0=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0")
LATEST=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "v0 has line1 only" "line1" "$V0"
assert_contains "latest has line1" "line1" "$LATEST"
assert_contains "latest has line2" "line2" "$LATEST"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 16: chmod on file NOT in cow_files ===${NC}"
echo "  chmod a fresh file (not previously written), check entry + commit"
########################################################################
echo "untouched" > "$WORKSPACE/test_cow.txt"
chmod 644 "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "chmod 755 $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry for chmod-only" "1" "$COUNT"

# Content should be identical to original
ORIG_CONTENT=$(cat "$WORKSPACE/test_cow.txt")
COW_CONTENT=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "cow content same as original" "$ORIG_CONTENT" "$COW_CONTENT"

# But cow file should have new perms
COW_PERMS=$(stat -c '%a' "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "cow file has 755" "755" "$COW_PERMS"

# Original should still be 644
ORIG_PERMS=$(stat -c '%a' "$WORKSPACE/test_cow.txt")
assert_eq "original still 644" "644" "$ORIG_PERMS"

# Commit and verify permissions are applied
commit_gen 999
FINAL_PERMS=$(stat -c '%a' "$WORKSPACE/test_cow.txt")
assert_eq "committed file has 755" "755" "$FINAL_PERMS"

# Content should still be same
FINAL_CONTENT=$(cat "$WORKSPACE/test_cow.txt")
assert_eq "content unchanged after chmod commit" "untouched" "$FINAL_CONTENT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 17: chmod + write in different commands ===${NC}"
echo "  chmod then write: should have 2 entries, both visible"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
chmod 644 "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "chmod 755 $WORKSPACE/test_cow.txt"
run_cmd "echo modified > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries (chmod + write)" "2" "$COUNT"

# v0 should have original content with 755 perms
V0_CONTENT=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0")
V0_PERMS=$(stat -c '%a' "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0")
assert_eq "v0 content = original" "original" "$V0_CONTENT"
assert_eq "v0 perms = 755" "755" "$V0_PERMS"

# latest should have new content
LATEST=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "latest has modified content" "modified" "$LATEST"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 18: Unlink cow-created file ===${NC}"
echo "  Create a file then rm it — should succeed and remove cow entries"
########################################################################
rm -f "$WORKSPACE/test_cow3.txt"
start_supervisor

run_cmd "echo created > $WORKSPACE/test_cow3.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry after create" "1" "$COUNT"

run_cmd "rm $WORKSPACE/test_cow3.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "0 entries after unlink cow-created file" "0" "$COUNT"

# File should not exist on real disk
assert_eq "file not on disk" "false" "$([ -f $WORKSPACE/test_cow3.txt ] && echo true || echo false)"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 19: Unlink real file — should be DENIED ===${NC}"
echo "  Try to rm a file on the real filesystem — must fail"
########################################################################
echo "real_file" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "rm $WORKSPACE/test_cow.txt 2>/dev/null || true"

# File should still exist
assert_eq "real file still exists" "true" "$([ -f $WORKSPACE/test_cow.txt ] && echo true || echo false)"
CONTENT=$(cat "$WORKSPACE/test_cow.txt")
assert_eq "real file content unchanged" "real_file" "$CONTENT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 20: DAG collapse — write same content twice ===${NC}"
echo "  Write 'hello' then 'hello' again — should collapse to 1 entry"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo hello > $WORKSPACE/test_cow.txt"
run_cmd "echo hello > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
# Two writes with identical content — DAG should collapse to 1
assert_eq "1 entry after DAG collapse (idempotent writes)" "1" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 21: DAG collapse — net-zero change ===${NC}"
echo "  Write 'modified' then write back 'original' — should show 0 entries"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo modified > $WORKSPACE/test_cow.txt"
run_cmd "echo original > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
# Final state == original → entire chain eliminated
assert_eq "0 entries after net-zero DAG collapse" "0" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 22: DAG collapse — keep real changes ===${NC}"
echo "  A→B→C where all differ — should keep all 3"
########################################################################
echo "A" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo B > $WORKSPACE/test_cow.txt"
run_cmd "echo C > $WORKSPACE/test_cow.txt"
run_cmd "echo D > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "3 entries when all versions differ" "3" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 23: DAG collapse — A→B→B→C keeps A→B, B→C ===${NC}"
echo "  Duplicate middle version collapses"
########################################################################
echo "A" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo B > $WORKSPACE/test_cow.txt"
run_cmd "echo B > $WORKSPACE/test_cow.txt"
run_cmd "echo C > $WORKSPACE/test_cow.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
# B→B collapses, so: first B entry + C entry = 2
assert_eq "2 entries after collapsing duplicate middle" "2" "$COUNT"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 24: Create + unlink + recreate ===${NC}"
echo "  Create file, delete it, create again — should show 1 entry"
########################################################################
rm -f "$WORKSPACE/test_cow3.txt"
start_supervisor

run_cmd "echo first > $WORKSPACE/test_cow3.txt"
run_cmd "rm $WORKSPACE/test_cow3.txt"
run_cmd "echo second > $WORKSPACE/test_cow3.txt"

COW_JSON=$(list_cow)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry after create+delete+recreate" "1" "$COUNT"

# Commit and verify final content
commit_gen 999
CONTENT=$(cat "$WORKSPACE/test_cow3.txt")
assert_eq "recreated file has 'second'" "second" "$CONTENT"

rm -f "$WORKSPACE/test_cow3.txt"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 25: Review levels — A→B→B→C scenario ===${NC}"
echo "  strict=2 (B→B collapsed), medium=2, loose=1 (only final)"
########################################################################
echo "A" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo B > $WORKSPACE/test_cow.txt"
run_cmd "echo B > $WORKSPACE/test_cow.txt"
run_cmd "echo C > $WORKSPACE/test_cow.txt"

S=$(list_cow strict | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
M=$(list_cow medium | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
L=$(list_cow loose  | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "strict: 2 entries (B→B collapsed, diff=0)" "2" "$S"
assert_eq "medium: 2 entries (B→B collapsed)" "2" "$M"
assert_eq "loose: 1 entry (only final C)" "1" "$L"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 26: Review levels — net-zero scenario ===${NC}"
echo "  Write modified then write back original"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo modified > $WORKSPACE/test_cow.txt"
run_cmd "echo original > $WORKSPACE/test_cow.txt"

S=$(list_cow strict | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
M=$(list_cow medium | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
L=$(list_cow loose  | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "strict: 2 entries (both kept)" "2" "$S"
assert_eq "medium: 0 entries (net-zero eliminated)" "0" "$M"
assert_eq "loose: 0 entries (net-zero eliminated)" "0" "$L"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 27: Review levels — all different ===${NC}"
echo "  A→B→C→D, no collapse possible"
########################################################################
echo "A" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo B > $WORKSPACE/test_cow.txt"
run_cmd "echo C > $WORKSPACE/test_cow.txt"
run_cmd "echo D > $WORKSPACE/test_cow.txt"

S=$(list_cow strict | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
M=$(list_cow medium | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
L=$(list_cow loose  | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "strict: 3" "3" "$S"
assert_eq "medium: 3 (no collapse)" "3" "$M"
assert_eq "loose: 1 (only D)" "1" "$L"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 28: Review levels — idempotent writes ===${NC}"
echo "  Write same content 3 times"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
start_supervisor

run_cmd "echo same > $WORKSPACE/test_cow.txt"
run_cmd "echo same > $WORKSPACE/test_cow.txt"
run_cmd "echo same > $WORKSPACE/test_cow.txt"

S=$(list_cow strict | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
M=$(list_cow medium | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
L=$(list_cow loose  | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "strict: 1 (consecutive identical collapsed even in strict)" "1" "$S"
assert_eq "medium: 1" "1" "$M"
assert_eq "loose: 1" "1" "$L"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 29: Parallel commands — different files ===${NC}"
echo "  Two commands run concurrently writing different files, each gets own cmd_id"
########################################################################
echo "original_a" > "$WORKSPACE/test_cow.txt"
echo "original_b" > "$WORKSPACE/test_cow2.txt"
start_supervisor

# Run two commands in parallel with different SCARLET_CMD_IDs
SANDBOX_SOCK_PATH="$BASE/$SESSION.notify.sock" \
LD_PRELOAD="$DIR/build/sandbox_preload.so" \
SCARLET_CMD_ID="parallel_A" \
    bash -c "echo parallel_a > $WORKSPACE/test_cow.txt" 2>/dev/null &
PID1=$!

SANDBOX_SOCK_PATH="$BASE/$SESSION.notify.sock" \
LD_PRELOAD="$DIR/build/sandbox_preload.so" \
SCARLET_CMD_ID="parallel_B" \
    bash -c "echo parallel_b > $WORKSPACE/test_cow2.txt" 2>/dev/null &
PID2=$!

wait $PID1 $PID2

COW_JSON=$(list_cow strict)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries from parallel cmds" "2" "$COUNT"

# Each entry should have a different cmd_id
CMD_IDS=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries;console.log([...new Set(e.map(x=>x.cmd_id))].sort().join(','))})")
assert_eq "2 distinct cmd_ids" "parallel_A,parallel_B" "$CMD_IDS"

# Both should have the same generation? No — different cmd_ids get different generations
GENS=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries;console.log([...new Set(e.map(x=>x.generation))].length)})")
assert_eq "2 distinct generations" "2" "$GENS"

# COMMIT_GEN with the lower generation should commit only one file
LOWER_GEN=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries;console.log(Math.min(...e.map(x=>x.generation)))})")
commit_gen "$LOWER_GEN"

# One file should be committed, one still in cow
REMAINING=$(list_cow strict | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "1 entry remaining after partial commit" "1" "$REMAINING"

cleanup

########################################################################
echo -e "\n${CYAN}=== Test 30: Parallel commands — same file ===${NC}"
echo "  Two commands write to the same file concurrently, each gets own version"
########################################################################
echo "original" > "$WORKSPACE/test_cow.txt"
start_supervisor

# First command writes
SANDBOX_SOCK_PATH="$BASE/$SESSION.notify.sock" \
LD_PRELOAD="$DIR/build/sandbox_preload.so" \
SCARLET_CMD_ID="same_file_A" \
    bash -c "echo version_A > $WORKSPACE/test_cow.txt" 2>/dev/null

# Second command writes to same file (different cmd_id = snapshot)
SANDBOX_SOCK_PATH="$BASE/$SESSION.notify.sock" \
LD_PRELOAD="$DIR/build/sandbox_preload.so" \
SCARLET_CMD_ID="same_file_B" \
    bash -c "echo version_B > $WORKSPACE/test_cow.txt" 2>/dev/null

COW_JSON=$(list_cow strict)
COUNT=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{console.log(JSON.parse(d).count)})")
assert_eq "2 entries for same file, different cmd_ids" "2" "$COUNT"

# Entries should have different cmd_ids
CMD_IDS=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries;console.log([...new Set(e.map(x=>x.cmd_id))].sort().join(','))})")
assert_eq "cmd_ids are same_file_A and same_file_B" "same_file_A,same_file_B" "$CMD_IDS"

# Same cmd_id entries should share the same generation
GEN_A=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries.find(x=>x.cmd_id==='same_file_A');console.log(e.generation)})")
GEN_B=$(echo "$COW_JSON" | node -e "process.stdin.on('data',d=>{const e=JSON.parse(d).entries.find(x=>x.cmd_id==='same_file_B');console.log(e.generation)})")
assert_eq "different generations for different cmd_ids" "true" "$([ "$GEN_A" != "$GEN_B" ] && echo true || echo false)"

# v0 should have version_A, latest should have version_B
V0=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.v0")
LATEST=$(cat "$BASE/$SESSION/cow_files$WORKSPACE/test_cow.txt")
assert_eq "v0 = version_A" "version_A" "$V0"
assert_eq "latest = version_B" "version_B" "$LATEST"

# Commit only first generation (version_A)
commit_gen "$GEN_A"
DISK=$(cat "$WORKSPACE/test_cow.txt")
assert_eq "disk has version_A after partial commit" "version_A" "$DISK"

cleanup

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "========================================"

# Cleanup test files
rm -f "$WORKSPACE/test_cow3.txt"

exit $FAIL
