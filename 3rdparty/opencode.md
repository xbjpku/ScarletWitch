# opencode (sandbox fork)

Fastcode requires a patched version of opencode with sandbox integration.

- **Repo**: https://github.com/xbjpku/opencode
- **Branch**: `sandbox-integration`
- **Commit**: [`b44883190`](https://github.com/xbjpku/opencode/commit/b44883190) — feat: add Fastcode sandbox integration
- **Upstream**: https://github.com/anomalyco/opencode (branch `dev`, tag `v1.3.17`)

## What the patch adds

- `config.ts`: `sandbox` config section (preload, supervisor, whitelist, dir)
- `bash.ts`: per-session supervisor lifecycle + `LD_PRELOAD` / `SANDBOX_SOCK_PATH` env injection
- `app.tsx`: `/enable_sandbox` slash command to toggle sandbox at runtime

## Setup

```json
// .opencode/opencode.json
{
  "sandbox": {
    "preload": "/path/to/Fastcode/build/sandbox_preload.so",
    "supervisor": "/path/to/Fastcode/build/supervisor",
    "whitelist": "/path/to/Fastcode/whitelist.conf",
    "dir": "/tmp/fastcode"
  }
}
```

## Build from source

```bash
git clone https://github.com/xbjpku/opencode.git
cd opencode
git checkout sandbox-integration
bun install
bun run build
```
