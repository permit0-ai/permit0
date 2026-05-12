# 01 — Codex Hook Wire Protocol

**Status:** Draft
**Revised:** 2026-05-10
**Depends on:** 00-overview
**Blocks:** 02-implementation

## Overview

Codex hooks are subprocess commands invoked by the Codex runtime. Each hook
receives a JSON object on **stdin** and may write a JSON response to **stdout**.
The exit code and stdout content together determine the hook's effect.

This document specifies the exact wire format for the `PreToolUse` hook (the
primary integration point) and the `PermissionRequest` hook (future v2).

## PreToolUse Stdin Schema

Codex sends a JSON object with both common fields and PreToolUse-specific
fields. The permit0 hook must accept and parse this superset.

```json
{
  "session_id": "019dba93-8214-7d50-a089-9690b4ce6b9e",
  "transcript_path": "/home/user/.codex/history/019dba93.jsonl",
  "cwd": "/home/user/project",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.4",
  "turn_id": "turn-7",
  "tool_name": "mcp__permit0-gmail__gmail_send",
  "tool_use_id": "call_abc123",
  "tool_input": {
    "to": "alice@example.com",
    "subject": "Meeting notes",
    "body": "Here are the notes..."
  }
}
```

### Field Reference

| Field | Type | Always present | Notes |
|-------|------|---------------|-------|
| `session_id` | string | Yes | Thread/session UUID. Primary session ID source for permit0. |
| `transcript_path` | string or null | Yes (may be null) | Path to JSONL transcript. Not used by permit0. |
| `cwd` | string | Yes | Working directory. Not used by permit0 directly. |
| `hook_event_name` | string | Yes | Always `"PreToolUse"` for this hook. |
| `model` | string | Yes | Active model slug. Not used by permit0. |
| `turn_id` | string | Yes | Codex turn identifier. Can be logged for audit correlation. |
| `tool_name` | string | Yes | Tool name, potentially MCP-prefixed. |
| `tool_use_id` | string | Yes | Unique call ID for this invocation. |
| `tool_input` | JSON value | Yes | Tool-specific parameters. Becomes `RawToolCall.parameters`. |

### Comparison with Claude Code stdin

Claude Code sends only `tool_name` and `tool_input`. Codex sends a superset
with session, turn, and environment metadata. The permit0 hook must
deserialize from a struct that accepts both formats:

```
Claude Code:  { tool_name, tool_input }
Codex:        { tool_name, tool_input, session_id, turn_id, cwd, model,
                hook_event_name, tool_use_id, transcript_path }
```

The implementation should use `#[serde(default)]` for all Codex-specific fields
so the same struct works for both clients.

## PreToolUse Stdout Schema

### Verdict: Allow (no objection)

Exit code `0` with **empty stdout** (zero bytes). Codex interprets this as
"hook ran successfully and has no objection." The tool executes normally.

**Critical:** Do NOT output `{ "permissionDecision": "allow" }`. Codex
explicitly rejects this and the tool will **fail open** (execute anyway with a
warning).

### Verdict: Deny (block)

Exit code `0` with JSON on stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "permit0: email.send (gmail) blocked — risk 82/100 CRITICAL [OUTBOUND, EXPOSURE, GOVERNANCE]"
  }
}
```

Codex also accepts the legacy block format (but prefer the envelope):

```json
{
  "decision": "block",
  "reason": "permit0: email.send (gmail) blocked — risk 82/100 CRITICAL"
}
```

### Verdict: Deny via exit code

Exit code `2` with the reason on **stderr**. Codex treats this as a block.
Not recommended for permit0 since it loses structured output.

### Verdict: Defer (no opinion)

Same as Allow: exit code `0` with empty stdout. Codex continues with its
normal flow. Used by `--unknown defer` when permit0 has no pack for the tool.

### Verdict: HITL / Ask User (not directly supported)

Codex `PreToolUse` does not support `permissionDecision: "ask"`. The v1
integration maps `HumanInTheLoop` to `deny` with an informative reason:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "permit0: email.send (gmail) — risk 62/100 HIGH — requires human review [OUTBOUND, EXPOSURE]. Re-run with explicit approval or add to allowlist."
  }
}
```

### System Message (informational context)

The hook can inject a system message without blocking:

```json
{
  "systemMessage": "permit0: email.send scored 28/100 (Low). Approved."
}
```

This is parsed by Codex but `additionalContext` injection into model
continuations is not fully supported yet. Useful for logging/observability
but not for enforcement.

## Verdict Mapping Table

| permit0 Permission | Codex PreToolUse output | Exit code |
|---------------------|------------------------|-----------|
| `Allow` | Empty stdout | 0 |
| `Deny` | `hookSpecificOutput` with `permissionDecision: "deny"` | 0 |
| `HumanInTheLoop` | `hookSpecificOutput` with `permissionDecision: "deny"` (v1) | 0 |
| Defer (unknown tool) | Empty stdout | 0 |
| Internal error | `hookSpecificOutput` with `permissionDecision: "deny"` (fail-closed) | 0 |

Compare with Claude Code:

| permit0 Permission | Claude Code output |
|---------------------|--------------------|
| `Allow` | `permissionDecision: "allow"` |
| `Deny` | `permissionDecision: "deny"` |
| `HumanInTheLoop` | `permissionDecision: "ask"` |
| Defer | Omit `permissionDecision` key |

Note: the daemon serializes `HumanInTheLoop` as `"human"` on the wire (not
`"humanintheloop"`). A prerequisite fix updates the hook remote mapper to
recognize both values (see `02-implementation.md`).

## MCP Tool Name Format

Codex uses the same `mcp__<server>__<tool>` convention as Claude Code for MCP
tool names. The double-underscore separator is identical.

Examples:
- `mcp__permit0-gmail__gmail_send` -> `gmail_send`
- `mcp__permit0-outlook__outlook_archive` -> `outlook_archive`
- `Bash` -> `Bash` (built-in, no prefix)
- `apply_patch` -> `apply_patch` (built-in, no prefix)

Codex additionally sanitizes MCP tool names for the Responses API: hyphens are
replaced with underscores and characters are restricted to ASCII alphanumeric
plus underscore. The permit0 hook receives the **pre-sanitized** name from
hooks, so the stripping logic is identical to Claude Code's `ClientKind::ClaudeCode`.

## Session ID Extraction

Codex provides session identity through multiple channels. The hook uses
them in this priority order (consistent with the existing Claude Code path
where the explicit flag is always the operator override):

1. **`--session-id` CLI flag** — Explicit operator override. Highest priority.

2. **`session_id` from stdin JSON** — Always present in Codex hook payloads.
   This is the thread UUID and the most reliable automatic source.

3. **`CODEX_THREAD_ID` environment variable** — Injected by Codex into shell
   tool processes. Available as a fallback but may not be set for all hook
   invocation contexts.

4. **PPID / cwd hash** — Existing fallback from the Claude Code path. Least
   reliable but ensures a session ID always exists.

```rust
fn derive_session_id_codex(
    stdin_session_id: Option<String>,
    explicit_flag: Option<String>,
) -> String {
    // 1. Explicit --session-id flag (operator override)
    if let Some(id) = explicit_flag {
        return id;
    }
    // 2. session_id from Codex stdin payload
    if let Some(id) = stdin_session_id.filter(|s| !s.is_empty()) {
        return id;
    }
    // 3. CODEX_THREAD_ID env var
    if let Ok(id) = std::env::var("CODEX_THREAD_ID") {
        if !id.is_empty() {
            return id;
        }
    }
    // 4. PPID / cwd hash fallback (existing logic)
    derive_session_id(None)
}
```

## Error Handling

| Scenario | Codex behavior |
|----------|---------------|
| Hook exits 0, empty stdout | Success; tool executes |
| Hook exits 0, valid deny JSON | Tool blocked with reason |
| Hook exits 0, invalid JSON | Codex logs warning; tool executes (fail-open) |
| Hook exits 1 (error) | Codex logs error; tool executes (fail-open) |
| Hook exits 2, reason on stderr | Tool blocked with stderr as reason |
| Hook times out | Codex logs timeout; tool executes (fail-open) |
| Hook crashes/segfaults | Codex logs error; tool executes (fail-open) |

**Protocol rule:** In Codex mode, every recoverable permit0 error after
process start **must** emit either a valid deny envelope on stdout (exit 0)
or exit code 2 with the error on stderr. The implementation wraps the Codex
path in a catch-all that converts `anyhow::Error` into a deny envelope (see
`02-implementation.md` Change 6). The current `?`-based error propagation
that works for Claude Code (non-zero exit = Claude prompts the user) is
**unsafe for Codex** (non-zero exit = tool executes).

**Implication:** permit0 must handle all errors gracefully and either output
a valid deny envelope or exit 0 cleanly. Any panic, crash, or malformed
output results in the tool executing unblocked.

## PermissionRequest Hook (v2, Future)

The `PermissionRequest` hook fires when Codex is about to prompt the user
for approval (sandbox escalation, network access, side-effecting MCP calls).
Unlike `PreToolUse`, it supports both `allow` and `deny` decisions:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow"
    }
  }
}
```

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "deny",
      "message": "permit0: blocked by policy"
    }
  }
}
```

Note: `PermissionRequest` uses `decision.behavior` (nested object), NOT
`permissionDecision` (flat string) -- a different envelope shape than
`PreToolUse`. Future v2 implementers must not copy the `PreToolUse` format.

This enables true HITL routing: `PreToolUse` can allow the call to proceed to
Codex's approval prompt, and `PermissionRequest` can then allow or deny based
on permit0's risk assessment. This is the planned v2 approach for handling
`Permission::HumanInTheLoop`.
