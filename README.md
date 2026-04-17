# ScarletWitch

> *"I don't need you to tell me who I am."* — Wanda Maximoff

**ScarletWitch** is a Linux seccomp-based filesystem sandbox for AI coding agents. Like the Scarlet Witch's Hex, it warps reality for the processes inside — all bash commands execute without asking for permission, but nothing touches the real world. All mutations are trapped in a **copy-on-write illusion** until you decide what becomes canon. And unlike other sandboxes that force you to re-run the entire agent after review, ScarletWitch lets you **turn illusion into reality with a single commit** — no replays, no do-overs. You are the strongest Scarlet Witch.

- **Hex Shield.** Your agent runs at full speed with zero interruptions — every action succeeds, but the real filesystem stays untouched.
- **Post-review Reality.** After a turn completes, review all changes, approve only what you want — approved changes become real *instantly*, no re-execution needed.
- **Chaos Simplification.** The DAG simplifier collapses redundant operations and surfaces only the changes that actually matter — less noise, faster approval.

Designed to work with [opencode](https://github.com/xbjpku/opencode) (branch `sandbox-integration`), but the supervisor is a standalone binary — anything that runs under `LD_PRELOAD` can be hexed.

## How it works

```
┌─────────────────────────────────────────────────────┐
│  Child process (bash, python, etc.)                 │
│  LD_PRELOAD=sandbox_preload.so                      │
│    ├─ installs seccomp BPF filter                   │
│    ├─ sends notify fd to supervisor via Unix socket  │
│    └─ applies Landlock read restrictions             │
└──────────────────┬──────────────────────────────────┘
                   │ seccomp user notifications
                   ▼
┌─────────────────────────────────────────────────────┐
│  Supervisor (Rust, async tokio)                     │
│    ├─ intercepts: openat, mkdir, rename, symlink,   │
│    │   chmod, truncate, unlink (cow-created only)   │
│    ├─ COW layer: writes go to /tmp/scarletwitch/ses_*/  │
│    ├─ per-command versioning (BEGIN_COMMAND protocol)│
│    ├─ DAG simplification (strict/medium/loose)      │
│    └─ control socket: LIST_COW, COMMIT, DISCARD     │
└─────────────────────────────────────────────────────┘
```

**Key features:**

- **Zero-copy interception** — seccomp user notifications + fd injection, no ptrace overhead
- **Per-command snapshots** — each bash tool call gets its own generation; reopening a file in a new command creates a versioned copy (`.v0`, `.v1`, ...)
- **Three review levels** — `strict` (show all actions that affect the filesys, for the most thorough review), `medium` (skip intermediate steps that don't affect the final filesystem state), `loose` (only the final diff of each changed file)
- **Selective commit** — commit the first N commands as a prefix, or commit/discard all

## Prerequisites

- Linux 5.9+ (seccomp user notifications)
- Rust toolchain (for supervisor)
- GCC (for preload shared library)

## Build

```bash
git clone https://github.com/xbjpku/ScarletWitch.git
cd ScarletWitch
make
```

Produces three binaries in `build/`:
- `supervisor` — the Rust sandbox supervisor
- `sandbox_preload.so` — LD_PRELOAD library for child processes
- `reload` — utility to hot-reload whitelist config

## Usage

### With opencode

Add to `.opencode/opencode.json`:

```json
{
  "sandbox": {
    "preload": "/path/to/ScarletWitch/build/sandbox_preload.so",
    "supervisor": "/path/to/ScarletWitch/build/supervisor",
    "whitelist": "/path/to/ScarletWitch/whitelist.conf",
    "dir": "/tmp/scarletwitch",
    "review": "medium"
  }
}
```

opencode will automatically start the supervisor, sandbox bash commands, and show a COW commit dialog after each turn for you to review and approve file changes.

The current integration is a minimal fork of opencode with invasive harness changes. A plugin-based integration for Claude Code and OpenClaw is under development — no fork required.

### Standalone

The supervisor is a standalone binary that can sandbox any process:

```bash
# Start supervisor for a session
./build/supervisor --session my_session --dir /tmp/scarletwitch --from whitelist.conf &

# Run a command under the sandbox
SANDBOX_SOCK_PATH="/tmp/scarletwitch/my_session.notify.sock" \
LD_PRELOAD="./build/sandbox_preload.so" \
    bash -c "echo hello > /some/protected/file.txt"

# Query changes
echo "LIST_COW" | nc -U /tmp/scarletwitch/my_session.ctrl.sock

# Commit all changes
echo 'COMMIT ["/some/protected/file.txt"]' | nc -U /tmp/scarletwitch/my_session.ctrl.sock

# Or discard everything
echo "DISCARD" | nc -U /tmp/scarletwitch/my_session.ctrl.sock
```

## Whitelist config

```ini
[write]
# Paths listed here are writable WITHOUT going through COW (pass-through).
# Everything else is intercepted.
/tmp/
/home/user/project/

[read]
# Paths listed here are NOT readable (blacklist).
# Everything else is readable by default.
/secret/data/
```

## Control protocol

The supervisor listens on a Unix socket (`{dir}/{session}.ctrl.sock`) for line-based commands:

| Command | Description |
|---------|-------------|
| `BEGIN_COMMAND` | Increment generation counter (new bash command starting) |
| `LIST_COW [strict\|medium\|loose]` | List pending COW entries as JSON (default: `medium`) |
| `COMMIT ["/path1","/path2"]` | Commit selected files (copy COW → real path) |
| `COMMIT_GEN <N>` | Commit all entries with generation ≤ N |
| `DISCARD` | Discard all COW state |
| `RELOAD` | Hot-reload whitelist config from disk |

## Tests

```bash
./test.sh
```

Runs 28 tests (84 assertions) covering all intercepted syscalls, per-command snapshots, DAG simplification levels, partial commit, cow-layer unlink, and edge cases.

## Project structure

```
ScarletWitch/
├── supervisor/src/
│   ├── main.rs        # async event loop, control socket, signal handling
│   ├── cow.rs         # COW table, versioning, DAG simplification, commit/discard
│   ├── dispatch.rs    # syscall routing and per-syscall handlers
│   ├── notif.rs       # seccomp ioctl wrappers (notify, inject fd)
│   ├── path.rs        # /proc/{pid}/mem path resolution
│   └── whitelist.rs   # double-buffered whitelist rule engine
├── src/
│   ├── sandbox_preload.c  # LD_PRELOAD: seccomp + Landlock + notify fd
│   └── reload.c           # whitelist hot-reload utility
├── 3rdparty/
│   └── opencode.md        # opencode fork reference
├── whitelist.conf          # default permission config
├── test.sh                 # integration tests
└── Makefile
```

## License

MIT
