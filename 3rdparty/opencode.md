# opencode (sandbox fork)

Fastcode requires a patched version of opencode with sandbox integration.

- **Repo**: https://github.com/xbjpku/opencode
- **Branch**: `sandbox-integration`
- **Commit**: [`785aa83fc`](https://github.com/xbjpku/opencode/commit/785aa83fc) — feat: per-command COW dialog with two-level navigation and diff viewing
- **Upstream**: https://github.com/anomalyco/opencode (branch `dev`, tag `v1.3.17`)

## What the patch adds

- `config.ts`: `sandbox` config section (preload, supervisor, whitelist, dir, review level)
- `bash.ts`: per-session supervisor lifecycle, `LD_PRELOAD` / `SANDBOX_SOCK_PATH` env injection, `BEGIN_COMMAND` protocol, `commitCowGen` / `listCowEntries` with review level
- `event.ts`: `CowEntry` schema with generation field for per-command tracking
- `prompt.ts`: post-task COW check with configurable review level
- `dialog-cow.tsx`: two-level COW commit dialog (cmd/file navigation, inline diff, prefix-based commit)

## Setup

```json
// .opencode/opencode.json
{
  "sandbox": {
    "preload": "/path/to/Fastcode/build/sandbox_preload.so",
    "supervisor": "/path/to/Fastcode/build/supervisor",
    "whitelist": "/path/to/Fastcode/whitelist.conf",
    "dir": "/tmp/fastcode",
    "review": "medium"
  }
}
```

Review levels: `"strict"` (all versions), `"medium"` (DAG simplified, default), `"loose"` (final state only).

## Build from source

```bash
git clone https://github.com/xbjpku/opencode.git
cd opencode
git checkout sandbox-integration
bun install
bun run build
```
