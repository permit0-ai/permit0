# 03 — Configuration Guide

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** 02-implementation

## Prerequisites

1. Build permit0 from source:

   ```bash
   git clone https://github.com/permit0-ai/permit0.git && cd permit0
   cargo build --release
   ```

2. Install Codex CLI:

   ```bash
   npm install -g @openai/codex
   ```

3. Verify Codex hooks are supported. The `[features] codex_hooks = true`
   flag must be recognized by your Codex version. If Codex silently ignores
   the flag, update to a newer version. (The exact minimum version is TBD --
   confirm against Codex release notes before shipping this integration.)

## Step 1: Enable the Hooks Feature Flag

Codex hooks are behind a feature flag. Add this to `~/.codex/config.toml`:

```toml
[features]
hooks = true
```

> **Note:** Codex's published docs (developers.openai.com/codex/hooks) still
> show `codex_hooks = true`. As of Codex 0.130.0-alpha.5, `codex_hooks` is
> **deprecated** and Codex emits an error on startup if you use it. Use
> `hooks = true` instead. This is verified against the live binary; see
> `06-real-codex-testing.md` for the live test transcript.

The `hooks` feature is also `stable, true` by default in current Codex
(`codex features list`), so this line is technically redundant in 0.130+ but
keeps the config explicit and forward-compatible.

## Step 1.5: Trust Model (CRITICAL for `codex exec`)

Hooks declared in user-level config (`~/.codex/config.toml` or
`~/.codex/hooks.json`) are **silently skipped** until you explicitly trust
them via the TUI's `/hooks` panel. This is invisible in `codex exec` — the
hook subprocess never runs, no error is reported, and the tool executes as
if no hook were configured.

Pick one based on your use case:

### Interactive use (Codex TUI sessions)

1. Add the hook config (Step 2 below) to `~/.codex/config.toml`.
2. Launch `codex` interactively once. You'll see "1 hook needs review before
   it can run. Open /hooks to review it."
3. Type `/hooks`, navigate to permit0, press the key shown to mark trusted.
4. Future Codex sessions (interactive and `codex exec`) will honor the hook.
5. Re-review is required if you edit the hook command (Codex tracks a
   content hash and re-flags as "Modified since last trusted").

### Unattended use (`codex exec` in CI, scripts, automation)

Install the hook as a **managed preference**, which Codex treats as
MDM-sourced and always-trusted (no review required):

```bash
HOOK_TOML='[features]
hooks = true

[hooks]
managed_dir = "/abs/path/to/hook/scripts"
windows_managed_dir = "/abs/path/to/hook/scripts"

[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/abs/path/to/permit0 hook --client codex --unknown defer"
timeout = 30
statusMessage = "permit0 safety check"
'

defaults write com.openai.codex requirements_toml_base64 \
  -string "$(echo -n "$HOOK_TOML" | base64)"
```

To remove: `defaults delete com.openai.codex requirements_toml_base64`.

This writes to per-user macOS defaults (no `sudo`). On Linux/Windows the
equivalent paths are `/etc/codex/managed_config.toml` (root) or
workspace-managed cloud requirements; consult Codex's enterprise docs.

This is the path the permit0 end-to-end test in `06-real-codex-testing.md`
uses.

## Step 2: Configure the PreToolUse Hook

Choose one of two configuration formats. Both are equivalent.

### Option A: `~/.codex/hooks.json` (JSON)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permit0 hook --client codex --remote http://127.0.0.1:9090 --unknown defer",
            "timeout": 30,
            "statusMessage": "permit0 safety check"
          }
        ]
      }
    ]
  }
}
```

### Option B: `~/.codex/config.toml` (inline TOML)

```toml
[features]
hooks = true

[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = '/abs/path/to/permit0 hook --client codex --remote http://127.0.0.1:9090 --unknown defer'
timeout = 30
statusMessage = "permit0 safety check"
```

TOML field-naming gotchas (verified live):

- Event keys are PascalCase: `PreToolUse`, `PermissionRequest`, `PostToolUse`,
  `SessionStart`, `UserPromptSubmit`, `Stop`. Snake-case keys silently
  deserialize to nothing because of serde renames.
- Inner handler fields are camelCase: `statusMessage` (not `status_message`).
- `timeout` is in **seconds** (not milliseconds), default 600.

**Important:**

- Use **absolute paths** to the `permit0` binary. Codex does not expand `~`.
- The `matcher` field is omitted so the hook runs for **all** tool calls
  (Bash, apply_patch, MCP tools). To restrict to specific tools, add
  `"matcher": "^(Bash|mcp__.*)$"`.
- The default timeout is 600 seconds. Set `timeout` to 30 for responsiveness.

## Step 3: Start the permit0 Daemon (Remote Mode)

Remote mode is recommended. The daemon handles evaluation, and the hook is a
lightweight HTTP forwarder:

```bash
# Terminal 1: start the daemon
cargo run -p permit0-cli -- serve --ui --port 9090

# Open http://localhost:9090/ui/ for the admin dashboard
```

The hook command (`--remote http://127.0.0.1:9090`) forwards each tool call
to the daemon's `POST /api/v1/check` endpoint.

### Network Access Requirement

In `workspace-write` sandbox mode, Codex blocks outbound network by default.
The hook subprocess needs to reach `127.0.0.1:9090` for `--remote` mode.
Enable network access in the sandbox config:

```toml
[sandbox_workspace_write]
network_access = true
```

Whether Codex sandboxes hook subprocesses the same way it sandboxes tool
commands is not documented. Enabling `network_access = true` is the safe
default that works regardless of Codex's hook sandboxing behavior. Verify
by running `permit0 hook --client codex --remote http://127.0.0.1:9090` with
a running daemon and confirming the hook can reach it.

## Configuration Variants

### Local Mode (No Daemon)

Evaluate in-process without an HTTP daemon. Simpler setup, but no shared
dashboard or audit trail:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permit0 hook --client codex --unknown defer",
            "timeout": 30,
            "statusMessage": "permit0 safety check"
          }
        ]
      }
    ]
  }
}
```

### Session-Aware Mode

Enable cross-invocation pattern detection (velocity, attack chains) with a
SQLite session store:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permit0 hook --client codex --db ~/.permit0/sessions.db --unknown defer",
            "timeout": 30,
            "statusMessage": "permit0 safety check (session-aware)"
          }
        ]
      }
    ]
  }
}
```

Note: `--db` is ignored when `--remote` is set. In v1, remote mode is
**stateless for session history** -- the hook does not forward `session_id`
in the POST body, and the daemon does not persist session action records.
Cross-call pattern detection (velocity, attack chains) only works in local
mode with `--db`. Remote session continuity is planned for v2.

### Shadow Mode (Observe Without Enforcing)

Log what permit0 would do to stderr without blocking any tool calls:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permit0 hook --client codex --remote http://127.0.0.1:9090 --shadow",
            "timeout": 30,
            "statusMessage": "permit0 shadow logging"
          }
        ]
      }
    ]
  }
}
```

Or set the environment variable `PERMIT0_SHADOW=1` to enable shadow mode
without changing the hook command.

### With a Profile (e.g., Fintech)

```toml
[[hooks.PreToolUse]]

[[hooks.PreToolUse.hooks]]
type = "command"
command = '/abs/path/to/permit0 hook --client codex --profile fintech --unknown defer'
timeout = 30
statusMessage = "permit0 fintech safety check"
```

### Calibration Mode

Start the daemon in calibration mode and every fresh decision blocks until a
human approves or denies in the dashboard:

```bash
# Terminal 1: calibration daemon
cargo run -p permit0-cli -- serve --ui --calibrate --port 9090
```

Hook config is the same `--remote` setup. Tool calls that hit
`Scorer`/`AgentReviewer`/`UnknownFallback` will block until a human
decides in the dashboard at `http://localhost:9090/ui/`.

If no human acts within the daemon's approval timeout, the request
returns HTTP 408. The Codex hook treats this as a deny with reason
"permit0 daemon error (HTTP 408)". Have an operator standing by when
using calibration mode, or increase the timeout in the daemon config.

### Project-Local Hooks

For per-repository configuration, place hooks in the project's `.codex/`
directory. These load only when the project is trusted:

```
my-project/
  .codex/
    hooks.json      # project-scoped hooks
    config.toml     # project-scoped config (optional)
```

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/to/permit0 hook --client codex --remote http://127.0.0.1:9090 --unknown deny",
            "timeout": 30,
            "statusMessage": "permit0 strict mode"
          }
        ]
      }
    ]
  }
}
```

Use `--unknown deny` for project-local hooks to enforce whitelist-only
governance: every tool without a pack is blocked.

## Matcher Examples

The `matcher` field is a regex applied to the tool name:

| Matcher | Effect |
|---------|--------|
| (omitted) | Match all tools |
| `".*"` | Match all tools (explicit wildcard) |
| `"^Bash$"` | Match only Bash tool calls |
| `"^(Bash\|apply_patch)$"` | Match Bash and file edits |
| `"^mcp__.*"` | Match only MCP tool calls |
| `"^mcp__permit0-gmail__.*"` | Match only Gmail MCP tools |
| `"^(Bash\|mcp__.*)$"` | Match Bash and all MCP tools |

For permit0, omitting the matcher (match all) is recommended so that
unrecognized tools are caught by the `--unknown` policy. Note that
`--unknown defer` delegates unrecognized tools to Codex's native behavior
(not permit0 governance). Use `--unknown deny` for whitelist-only setups
where every governed action must have a pack or allowlist entry.

## Environment Variable Overrides

All configuration can be set via environment variables for CI or automated
setups:

| Env Var | Overrides | Example |
|---------|-----------|---------|
| `PERMIT0_REMOTE` | `--remote` | `http://127.0.0.1:9090` |
| `PERMIT0_UNKNOWN` | `--unknown` | `defer` |
| `PERMIT0_SHADOW` | `--shadow` | `1` |
| `PERMIT0_CLIENT` | `--client` | `codex` |

Precedence: CLI flag > environment variable > default.

## MCP Server Configuration

If using Gmail or Outlook MCP servers, configure them in Codex's MCP section.
In `~/.codex/config.toml`:

```toml
[mcp_servers.permit0-gmail]
command = "/abs/path/to/permit0-gmail-mcp"

[mcp_servers.permit0-outlook]
command = "/abs/path/to/permit0-outlook-mcp"
```

Or via the `codex mcp add` command:

```bash
codex mcp add permit0-gmail -- /abs/path/to/permit0-gmail-mcp
codex mcp add permit0-outlook -- /abs/path/to/permit0-outlook-mcp
```

MCP tool calls from these servers arrive at the hook as
`mcp__permit0-gmail__gmail_send`, which the `--client codex` stripping
normalizes to `gmail_send` for pack matching.

## Codex-Specific Warnings

**Fail-open on errors:** Codex treats hook crashes, non-zero exits, timeouts,
and malformed stdout as "no objection" -- the tool executes. The permit0 Codex
adapter wraps all errors into deny envelopes to stay fail-closed, but you
should test with the daemon down (`--remote` pointing at a stopped port) to
verify deny behavior before going live.

**Daemon-down behavior:** When the remote daemon is unreachable, the Codex
adapter emits a deny with "permit0 remote unavailable" as the reason. This
is stricter than Claude Code (which prompts the user). If you prefer
fail-open when the daemon is down, use `--shadow` mode.

## Verification

After configuring, verify the integration:

1. Start Codex: `codex`
2. Ask it to do something that triggers a tool call:
   `"list recent emails and archive any newsletters"`
3. Check stderr for permit0 log output (shadow mode) or observe
   the dashboard at `http://localhost:9090/ui/`
4. Verify tool calls are blocked/allowed as expected
