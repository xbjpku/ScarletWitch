# ScarletWitch

> *"I have what I want, and no one will ever take it from me again."* — Wanda Maximoff

**ScarletWitch** is a Linux seccomp-based filesystem sandbox for AI coding agents. Like the Scarlet Witch's Hex, it warps reality for the processes inside — all bash commands execute without asking for permission, but nothing touches the real world. All mutations are trapped in a **copy-on-write illusion** until you decide what becomes canon. And unlike other sandboxes that force you to re-run the entire agent after review, ScarletWitch lets you **turn illusion into reality with a single commit** — no replays, no do-overs. You are the strongest Scarlet Witch.

- **Hex Shield.** Your agent runs automatically with zero interruptions — every action succeeds, but the real filesystem stays untouched and safe.
- **Post-review Reality.** Review changes, approve only what you want — approved changes become real *instantly*, no re-execution needed.
- **Chaos Simplification.** The DAG simplifier collapses redundant operations and surfaces only the changes that actually matter — less noise, faster approval.

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
│    ├─ COW layer: writes go to /tmp/scarletwitch/    │
│    ├─ per-command versioning (BEGIN_COMMAND protocol)│
│    ├─ DAG simplification (strict/medium/loose)      │
│    └─ control socket: LIST_COW, COMMIT, DISCARD     │
└─────────────────────────────────────────────────────┘
```

**Key features:**

- **Syscall-level sandboxing** — Intercepts dangerous filesystem syscalls (write, mkdir, rename, chmod, truncate) via seccomp user notifications. Destructive operations like `rm` on real files are denied. Read access is controlled by a simple whitelist to prevent disk scanning or secret leakage. Zero ptrace overhead.
- **Post-review only** — No mid-execution permission prompts. The agent runs at full speed while snapshots are recorded per command in the COW layer. You review everything *after* the turn completes — faster than interrupting every step.
- **Three review levels** — `strict` (show all actions that affect the filesystem, for the most thorough review), `medium` (skip intermediate steps that don't affect the final filesystem state), `loose` (only the final diff of each changed file)
- **Selective commit** — commit the first N commands as a prefix, or commit/discard all

## Quick Start

Use the [**ScarletWitch-opencode-plugin**](https://github.com/xbjpku/ScarletWitch-opencode-plugin) for the easiest setup — self-contained, no fork needed. Plugins for Claude Code and OpenClaw are under development.

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

## More Usage

### With opencode (fork)

Use the [integration fork](https://github.com/xbjpku/opencode/tree/integration) with built-in support. Add to `.opencode/opencode.json`:

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
├── whitelist.conf          # default permission config
├── test.sh                 # integration tests
└── Makefile
```

## License

MIT
