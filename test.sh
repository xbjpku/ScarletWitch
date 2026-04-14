#!/bin/bash
# Test script: starts supervisor, runs a command under sandbox, then cleans up.
# Usage: ./test.sh [command...]
# Default command: ls /mnt/user-ssd

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SESSION="test_$$"
BASE="/tmp/fastcode"
CONF="$DIR/whitelist.conf"
CMD="${@:-ls .}"

# Ensure clean state
mkdir -p "$BASE"
rm -f "$BASE/$SESSION".*

echo "=== Starting supervisor (session=$SESSION) ==="
"$DIR/build/supervisor" --session "$SESSION" --dir "$BASE" --from "$CONF" &
SV_PID=$!
sleep 0.5

# Check supervisor started
if ! kill -0 $SV_PID 2>/dev/null; then
    echo "ERROR: supervisor failed to start"
    exit 1
fi
echo "Supervisor PID: $SV_PID"
echo "Log: $BASE/$SESSION.log"
echo ""

echo "=== Running: $CMD ==="
SANDBOX_SOCK_PATH="$BASE/$SESSION.notify.sock" \
LD_PRELOAD="$DIR/build/sandbox_preload.so" \
    bash -c "$CMD" 2>&1
EXIT_CODE=$?
echo ""
echo "=== Command exit code: $EXIT_CODE ==="

echo ""
echo "=== Supervisor log ==="
cat "$BASE/$SESSION.log" 2>/dev/null

echo ""
echo "=== Supervisor CPU check ==="
sleep 1
if kill -0 $SV_PID 2>/dev/null; then
    ps -p $SV_PID -o pid,%cpu,stat --no-headers
fi

echo ""
echo "=== Cleanup ==="
kill $SV_PID 2>/dev/null
wait $SV_PID 2>/dev/null
rm -f "$BASE/$SESSION".*
echo "Done."
