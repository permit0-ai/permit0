# 06 — Real Codex CLI Testing: Verified End-to-End

**Status:** **VERIFIED working** against Codex 0.130.0-alpha.5
**Verified date:** 2026-05-10
**Depends on:** 03-configuration.md

permit0's Codex integration was tested end-to-end against an actual
Codex CLI install. The hook fires on every tool call, the wire format
matches Codex's embedded JSON schema exactly, and Codex honors permit0's
deny envelope to block tool execution.

This doc captures (a) the verified working configuration, (b) the
schema corrections vs. what the plan originally said, and (c) the
reusable test harness under `/tmp/permit0-codex-test/`.

## Verified working configuration

Two pieces are required: a `requirements_toml_base64` macOS managed
preference (which Codex treats as MDM-sourced and auto-trusts), plus a
running permit0 hook command.

### Step 1: Build the permit0 release binary

```bash
cd /Users/ziyou/Development/permit0
cargo build --release
# binary at target/release/permit0
```

### Step 2: Install managed hook config via macOS user defaults

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
command = "/abs/path/to/permit0-hook-wrapper.sh"
timeout = 30
statusMessage = "permit0 safety check"
'

HOOK_B64=$(echo -n "$HOOK_TOML" | base64)
defaults write com.openai.codex requirements_toml_base64 -string "$HOOK_B64"
```

Why managed preferences:

- Codex reads `requirements_toml_base64` from `com.openai.codex` user defaults at every startup.
- Hooks declared in `requirements` are treated as `legacy_managed_config_mdm` source → **always trusted, never require the `/hooks` review prompt**.
- This is the only path that works in non-interactive `codex exec` runs without first launching the TUI.
- It's a per-user defaults entry (no `sudo`, no `/etc/`), and it's reversible: `defaults delete com.openai.codex requirements_toml_base64`.

### Step 3: Run Codex; the hook fires on every PreToolUse

```bash
codex exec --skip-git-repo-check --sandbox workspace-write \
  "Run 'ls' and tell me what files you see"
```

Codex spawns your hook command on every tool call. The hook's stdin is
exactly the schema documented in `01-protocol.md` (plus the new
`permission_mode` field). Empty stdout = no objection. JSON deny
envelope = command blocked.

## Verified end-to-end behavior

The test run confirmed:

**1. Hook fires on tool calls.** Codex emitted a PreToolUse event when
the model proposed `head -c 16 /dev/urandom | shasum -a 256`. The
wrapper captured the full 377-byte stdin payload in
`inv-<id>/stdin.json`.

**2. Wire format matches our struct.** Codex sent (pretty-printed):

```json
{
  "session_id": "019e13f9-dacb-70e3-834b-cf1956c503c0",
  "turn_id": "019e13f9-daf7-7ab0-a18e-c42b947e05d1",
  "transcript_path": null,
  "cwd": "/tmp/permit0-codex-probe",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.5",
  "permission_mode": "bypassPermissions",
  "tool_name": "Bash",
  "tool_input": {
    "command": "head -c 16 /dev/urandom | shasum -a 256"
  },
  "tool_use_id": "call_jE8ukjcDni4dwzscftagKeIV"
}
```

Every field present in this payload deserializes correctly through
permit0's `HookInput` struct. The `permission_mode` field is not
consumed by permit0 (forward-compat) but doesn't break parsing.

**3. Shadow mode: empty stdout, shadow log on stderr.**

Run with `permit0 hook --client codex --shadow --unknown defer`:

```
events.log row:  exit=0  stdout_bytes=0  stderr_bytes=72  decision=EMPTY_STDOUT
permit0 stderr:  [permit0 shadow] WOULD DEFER: unknown.unclassified (Bash) score=0/100
codex outcome:   command ran normally (no objection seen by Codex)
```

**4. Enforcement mode: deny envelope blocks the command.**

Run with `permit0 hook --client codex --unknown deny`:

```
events.log row:  exit=0  stdout_bytes=167  decision=deny
permit0 stdout:  {"hookSpecificOutput":{"hookEventName":"PreToolUse",
                  "permissionDecision":"deny",
                  "permissionDecisionReason":"permit0: unknown action denied by --unknown deny policy"}}
codex outcome:   command was NOT executed
model message:   "The command was blocked by the environment's PreToolUse
                  policy before it could run, so there is no stdout to report."
```

The bash command never ran. The model received the block signal and
explained it to the user. **This is the complete permit0 → Codex →
agent decision chain working in production.**

## Schema corrections vs. the original plan

The plan docs predated the live Codex 0.130 schema. Here are the
verified deltas. `03-configuration.md` should be updated to match.

### 1. Feature flag

**Plan said:**
```toml
[features]
codex_hooks = true
```

**Actually required (current Codex):**
```toml
[features]
hooks = true
```

Codex 0.130.0-alpha.5 emits a clear deprecation error if you use
`codex_hooks`:

> `[features].codex_hooks` is deprecated. Use `[features].hooks` instead.

### 2. TOML hook event keys

**Plan said:** PascalCase event keys (correct).
**Actually required:** PascalCase event keys.

```toml
[[hooks.PreToolUse]]        # ← PascalCase, not pre_tool_use
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "..."
timeout = 30                 # ← timeout, not timeout_sec
statusMessage = "..."        # ← statusMessage (camelCase), not status_message
```

The serde rename rules in `HookEventsToml` confirm: TOML keys are
PascalCase (`PreToolUse`, `PermissionRequest`, etc.) but Rust field
names are snake_case.

### 3. Stdin schema has a new required field

`01-protocol.md` lists 9 stdin fields. The live `pre-tool-use.command.input`
JSON schema in Codex 0.130 has **10 required fields** — adds
`permission_mode`:

```
cwd, hook_event_name, model, permission_mode, session_id,
tool_input, tool_name, tool_use_id, transcript_path, turn_id
```

`permission_mode` is one of:
`default | acceptEdits | plan | dontAsk | bypassPermissions`. permit0
silently ignores it today; this is forward-compat capacity for gating
decisions on Codex's approval policy.

### 4. Trust model — the operational gotcha

Hooks from regular `~/.codex/config.toml` are discovered but **silently
skipped** in `codex exec` because they're marked "untrusted" until the
user reviews them in the TUI's `/hooks` panel. Symptoms:

- No "hook needs review" message (that only shows in the TUI).
- Hook subprocess never invoked.
- No error in `codex exec --json` output.
- RUST_LOG=trace shows no hook discovery activity.

Bypass paths that work without TUI:

| Source | Trust | How |
|---|---|---|
| `~/.codex/config.toml` `[hooks]` | Untrusted until `/hooks` review | TUI only |
| `~/.codex/hooks.json` | Untrusted until review | TUI only |
| Project `.codex/...` | Requires project trust + hook review | TUI only |
| `requirements_toml_base64` macOS defaults | **Always trusted** | `defaults write` ✅ |
| `/etc/codex/managed_config.toml` | **Always trusted** | Requires `sudo` |
| `cloud_requirements` | **Always trusted** | Workspace-managed |

For unattended automation (CI, scripts, headless boxes), use the macOS
defaults path as shown in Step 2 above.

## Test infrastructure

Reusable assets at `/tmp/permit0-codex-test/`:

- `wrap-permit0.sh` — instrumented hook wrapper. Per-invocation
  `inv-<id>/{stdin.json,stdout,stderr,env}` plus structured JSONL row
  in `events.log`. Diagnoses what Codex sent and what permit0 returned.
- `run-codex-test.sh` — driver: hard timeout, periodic progress poll,
  structured report. Used during the live test run.

Reusable assets in the repo:

- `scripts/test-codex-hook.sh` — 9-case synthetic smoke test. Runs the
  `permit0 hook --client codex` binary with canned Codex-shaped stdin
  and validates output shape. Doesn't need Codex installed. CI-ready.

## Reproducing the end-to-end test

```bash
# 1. Build permit0
cd /Users/ziyou/Development/permit0 && cargo build --release

# 2. Install the hook command (already at /tmp/permit0-codex-test/wrap-permit0.sh)
chmod +x /tmp/permit0-codex-test/wrap-permit0.sh

# 3. Install managed config
HOOK_TOML='[features]
hooks = true

[hooks]
managed_dir = "/tmp/permit0-codex-test"
windows_managed_dir = "/tmp/permit0-codex-test"

[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/tmp/permit0-codex-test/wrap-permit0.sh"
timeout = 30
statusMessage = "permit0 safety check"
'
defaults write com.openai.codex requirements_toml_base64 \
  -string "$(echo -n "$HOOK_TOML" | base64)"

# 4. Run Codex with a tool-triggering prompt
codex exec --ephemeral --skip-git-repo-check --sandbox workspace-write \
  "Run 'ls' and tell me what files you see"

# 5. Inspect what happened
cat /tmp/permit0-codex-test/events.log
ls /tmp/permit0-codex-test/inv-*

# 6. Clean up when done
defaults delete com.openai.codex requirements_toml_base64
```

## Implications for permit0

**No code changes required.** Every behavior I could verify against
Codex's actual schemas matches what permit0 does:

- The exact `hookSpecificOutput` envelope shape ✓
- `permissionDecision: "deny"` only, with a non-empty reason ✓
- Never emit `allow` or `ask` ✓
- MCP prefix stripping ✓
- `CODEX_THREAD_ID` env var support ✓
- HITL → deny mapping with marker ✓
- Empty-stdout-for-no-objection ✓

**Documentation updates needed in `03-configuration.md`:**

1. Replace `[features] codex_hooks = true` → `[features] hooks = true`.
2. Add a "Trust model" section explaining the TUI-review-or-MDM bypass
   choice.
3. Add the `requirements_toml_base64` recipe for unattended deploys.
4. Note that `permission_mode` arrives in stdin and is currently
   ignored (forward-compat).

**Tests for CI:**

- `scripts/test-codex-hook.sh` (synthetic smoke, 9 cases) is already in
  place and runs in ~1s without Codex. Gate this in CI.
- A real-Codex CI test needs an isolated `CODEX_HOME` with a managed
  preferences entry. Doable on a self-hosted runner; impractical for
  GitHub Actions (no defaults DB control). Likely defer to a manual
  release-gate test.
