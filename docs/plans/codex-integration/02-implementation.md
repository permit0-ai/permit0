# 02 — Implementation Plan

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** 00-overview, 01-protocol
**Blocks:** 03-configuration, 04-testing

## Summary

All changes are confined to `crates/permit0-cli/src/cmd/hook.rs` and
`crates/permit0-cli/src/main.rs`. No engine, scoring, pack, store, or daemon
changes are required. The implementation adds Codex as a new output format
that reuses the existing evaluation pipeline.

## Change 1: Add `Codex` to `ClientKind`

**File:** `crates/permit0-cli/src/cmd/hook.rs`

Add a `Codex` variant that uses the same `mcp__<server>__<tool>` stripping
as `ClaudeCode`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientKind {
    #[default]
    ClaudeCode,
    ClaudeDesktop,
    OpenClaw,
    Codex,       // <-- new
    Raw,
}

impl ClientKind {
    pub fn strip_prefix(self, tool_name: &str) -> &str {
        match self {
            Self::ClaudeCode | Self::Codex => tool_name
                .strip_prefix("mcp__")
                .and_then(|rest| rest.split_once("__").map(|(_, tool)| tool))
                .unwrap_or(tool_name),
            Self::OpenClaw => tool_name
                .split_once('.')
                .map(|(_, tool)| tool)
                .unwrap_or(tool_name),
            Self::ClaudeDesktop | Self::Raw => tool_name,
        }
    }
}
```

Update `FromStr`:

```rust
impl FromStr for ClientKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "claude-code" | "claude_code" => Ok(Self::ClaudeCode),
            "claude-desktop" | "claude_desktop" => Ok(Self::ClaudeDesktop),
            "openclaw" | "open-claw" | "open_claw" => Ok(Self::OpenClaw),
            "codex" | "codex-cli" | "codex_cli" => Ok(Self::Codex),  // <-- new
            "raw" | "none" => Ok(Self::Raw),
            other => Err(format!(
                "unknown client '{other}' (supported: claude-code, claude-desktop, \
                 openclaw, codex, raw)"
            )),
        }
    }
}
```

## Change 2: Add `OutputFormat` enum

**File:** `crates/permit0-cli/src/cmd/hook.rs`

Introduce an enum that controls how verdicts are serialized to stdout:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    ClaudeCode,
    Codex,
}

impl OutputFormat {
    pub fn from_client(client: ClientKind) -> Self {
        match client {
            ClientKind::Codex => Self::Codex,
            _ => Self::ClaudeCode,
        }
    }
}
```

## Change 3: Codex input deserialization

**File:** `crates/permit0-cli/src/cmd/hook.rs`

Expand `HookInput` to accept Codex's extended fields. All new fields are
optional with `#[serde(default)]` so the struct remains backward-compatible
with Claude Code's minimal `{ tool_name, tool_input }` payload:

```rust
#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub hook_event_name: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
}
```

This is a non-breaking change: existing Claude Code payloads deserialize
identically since all new fields default to `None`. Empty-string values from
Codex are treated as absent: downstream consumers use
`.filter(|s| !s.is_empty())` before acting on any Codex string field.

## Change 4: Codex output serialization

**File:** `crates/permit0-cli/src/cmd/hook.rs`

The Codex output layer converts a finalized `HookOutput` (which already has
unknown policy, shadow mode, and remote error rewrites applied) into Codex
wire format. This avoids duplicating the rewrite pipeline.

```rust
/// Build a Codex deny envelope JSON string.
fn codex_deny_envelope(reason: &str) -> Option<String> {
    let output = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    Some(serde_json::to_string(&output).expect("deny envelope serialization"))
}

/// Convert a finalized HookOutput into Codex stdout.
/// Returns `None` when the hook should exit 0 with empty stdout.
fn hook_output_to_codex(output: &HookOutput) -> Option<String> {
    match output.hook_specific_output.permission_decision {
        Some("allow") | None => None,
        Some("deny") | Some("ask") => codex_deny_envelope(
            output.hook_specific_output.permission_decision_reason
                .as_deref().unwrap_or("permit0 denied"),
        ),
        Some(other) => codex_deny_envelope(
            &format!("permit0: unexpected decision '{other}'"),
        ),
    }
}
```

For `HumanInTheLoop`, the reason string should include actionable context:

```
permit0: email.send (gmail) — risk 62/100 HIGH — requires human review
[OUTBOUND, EXPOSURE]. Add to allowlist via dashboard or re-run with approval.
```

## Change 5: Session ID extraction for Codex

**File:** `crates/permit0-cli/src/cmd/hook.rs`

Add a Codex-aware session ID derivation that reads from the stdin payload:

```rust
fn derive_session_id_for_format(
    format: OutputFormat,
    stdin_session_id: Option<String>,
    explicit_flag: Option<String>,
) -> String {
    if let Some(id) = explicit_flag {
        return id;
    }
    match format {
        OutputFormat::Codex => {
            // Codex provides session_id in stdin JSON
            if let Some(id) = stdin_session_id.filter(|s| !s.is_empty()) {
                return id;
            }
            // Fallback: CODEX_THREAD_ID env var
            if let Ok(id) = std::env::var("CODEX_THREAD_ID") {
                if !id.is_empty() {
                    return id;
                }
            }
            derive_session_id(None)
        }
        OutputFormat::ClaudeCode => derive_session_id(None),
    }
}
```

## Change 6: Update `run()` with Codex fail-closed error handling

**File:** `crates/permit0-cli/src/cmd/hook.rs`

**Critical constraint:** In Codex, a non-zero exit or malformed stdout causes
the tool to execute (fail-open). The current `run()` uses `?` on stdin
parsing, engine construction, permission evaluation, and output serialization.
Every one of those error paths would fail open in Codex.

The implementation must wrap the Codex path so that **every recoverable error
after process start emits a valid deny envelope or exit code 2**, never a
bare non-zero exit. Two approaches:

**Option A (recommended): Codex wrapper function.**

```rust
pub fn run(/* existing params */) -> Result<()> {
    let format = OutputFormat::from_client(client);
    match format {
        OutputFormat::ClaudeCode => run_claude(/* params */),
        OutputFormat::Codex => {
            match run_codex_inner(/* params */) {
                Ok(()) => Ok(()),
                Err(e) => {
                    // Fail closed: emit a deny envelope for the error.
                    let output = serde_json::json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason":
                                format!("permit0 internal error: {e}")
                        }
                    });
                    println!("{}", serde_json::to_string(&output)
                        .unwrap_or_else(|_| String::new()));
                    Ok(())
                }
            }
        }
    }
}
```

If even the JSON serialization of the error envelope fails, exit code 2 with
the error on stderr is the fallback (Codex treats exit 2 as a block).

**Option B: Exit code 2 for all errors.**

```rust
// In main.rs, after run() returns Err in Codex mode:
std::process::exit(2);
```

Option A is preferred because it provides a structured reason to the user.

### Remote mode, shadow mode, unknown mode

All three modes operate on `HookOutput` values today. The Codex path reuses
the same rewrite pipeline (unknown policy, shadow override, remote error
mapping) and converts the final `HookOutput` to Codex output at the very end:

```rust
fn hook_output_to_codex(output: &HookOutput) -> Option<String> {
    match output.hook_specific_output.permission_decision {
        Some("allow") | None => None, // exit 0, empty stdout
        Some("deny") => {
            // re-emit as Codex deny envelope
            codex_deny_envelope(output.hook_specific_output
                .permission_decision_reason.as_deref()
                .unwrap_or("permit0 denied"))
        }
        Some("ask") => {
            // Codex has no ask; map to deny with reason
            codex_deny_envelope(output.hook_specific_output
                .permission_decision_reason.as_deref()
                .unwrap_or("permit0: requires human review"))
        }
        Some(other) => {
            codex_deny_envelope(
                &format!("permit0: unexpected decision '{other}'"))
        }
    }
}
```

This avoids the `codex_output(Permission, reason)` function which was too
narrow to represent the full hook decision model (unknown policy rewrites,
remote errors, shadow allow).

For **shadow mode**, the Codex allow output is exit 0 with empty stdout.
The existing shadow path calls `println!("{}", serde_json::to_string(&HookOutput::allow())?)`,
which for Codex would emit `permissionDecision: "allow"` -- the forbidden
form. The implementation must branch:

```rust
if shadow {
    let (decision, reason) = hook_output_summary(&output);
    if decision != "allow" {
        eprintln!("[permit0 shadow] WOULD {} ...", decision.to_uppercase());
    }
    match format {
        OutputFormat::ClaudeCode => {
            println!("{}", serde_json::to_string(&HookOutput::allow())?);
        }
        OutputFormat::Codex => {
            // Skip stdout entirely -- zero bytes = no objection.
        }
    }
    return Ok(());
}
```

**Critical:** The Codex allow path must not call `println!("")` or
`print!("")` -- either would emit a trailing newline byte, which may trigger
Codex's invalid-JSON warning path. Skip the stdout write entirely.

For **`--unknown` mode**:
- `Defer` -> exit 0 with empty stdout (no opinion)
- `Allow` -> exit 0 with empty stdout
- `Deny` -> deny envelope with reason
- `Ask` -> deny envelope with reason (Codex has no "ask")

For **remote daemon-down** (transport error): the current Claude path maps to
`HookOutput::ask(...)`. The Codex conversion maps `ask` to deny, so Codex
fails closed. This is stricter than Claude Code behavior (which prompts the
user) and is the correct Codex behavior.

## Change 7: Update CLI argument parser

**File:** `crates/permit0-cli/src/main.rs`

Update the `--client` help text to include `codex`:

```rust
/// Which MCP host (agent) is calling the hook. Controls how
/// MCP tool-name prefixes are stripped and how verdicts are serialized.
/// Supported: claude-code (default), claude-desktop, openclaw, codex, raw.
/// Override via PERMIT0_CLIENT env var.
#[arg(long, value_name = "CLIENT")]
client: Option<String>,
```

No new CLI flags are needed. The `--client codex` value selects both the
correct prefix stripping and the Codex output format. The help text should
also include `openclaw` which is already supported in `ClientKind::from_str`
but missing from the current help string.

## Files Changed (Summary)

| File | Change type | Description |
|------|-------------|-------------|
| `crates/permit0-cli/src/cmd/hook.rs` | Modify | Add `Codex` to `ClientKind`, `OutputFormat` enum, expanded `HookInput`, Codex output functions, session ID derivation |
| `crates/permit0-cli/src/main.rs` | Modify | Update `--client` help text |

## Files NOT Changed (but transitively affected)

- `crates/permit0-cli/src/cmd/serve.rs` — No source edits, but gains
  `client_kind: "codex"` support via the shared `ClientKind` import

## Files NOT Changed

- `crates/permit0-engine/` — Engine pipeline is client-agnostic
- `crates/permit0-scoring/` — Scoring is client-agnostic
- `crates/permit0-normalize/` — Normalization is client-agnostic
- `crates/permit0-session/` — Session store is reused as-is
- `crates/permit0-store/` — Store is client-agnostic
- `crates/permit0-ui/` — Dashboard and daemon are unchanged
- `crates/permit0-cli/src/cmd/serve.rs` — Daemon API is unchanged
- `packs/` — Pack YAML is client-agnostic
- `profiles/` — Profiles are client-agnostic

## Migration Path for Existing Users

No migration needed. The `--client codex` flag is additive. Existing
`--client claude-code` (default) behavior is completely unchanged. Users
switching from Claude Code to Codex only need to:

1. Change their hook config from `settings.json` to `hooks.json` / `config.toml`
2. Add `--client codex` to the hook command
3. Enable `codex_hooks = true` in Codex config

## Prerequisite: Fix Remote HITL Wire Mismatch

Before implementing Codex support, fix the existing bug where the daemon
serializes `Permission::HumanInTheLoop` as `"human"` (via
`Permission::Display` -> `"HUMAN"` -> `to_lowercase()` in `serve.rs:578`)
but the hook remote mapper at `hook.rs:324` only matches `"humanintheloop"`.

The fix: add `"human"` as a recognized match arm in
`remote_response_to_hook_output`:

```rust
fn remote_response_to_hook_output(resp: &RemoteCheckResponse) -> HookOutput {
    match resp.permission.as_str() {
        "allow" => HookOutput::allow(),
        "deny" => HookOutput::deny(/* ... */),
        "human" | "humanintheloop" => HookOutput::ask(/* ... */),
        other => HookOutput::ask(/* fail-safe */),
    }
}
```

Add a test that pins the actual `serve.rs` response shape (`"human"`, not
`"humanintheloop"`). This fix benefits Claude Code remote mode too (currently
HITL shows a confusing "unknown permission value 'human'" reason).

## Risk Assessment

- **Low risk:** The change is entirely in the CLI I/O layer. The engine
  evaluation path is untouched.
- **Regression surface:** Claude Code hook behavior must be verified unchanged
  (existing test suite covers this).
- **Codex-specific risk:** Bugs in error handling or output serialization
  cause Codex to fail open (tool executes). The fail-closed wrapper in
  Change 6 mitigates this by catching errors and emitting deny envelopes,
  but any panic or signal-kill still fails open. Test coverage at the
  process boundary (not just unit level) is essential.
