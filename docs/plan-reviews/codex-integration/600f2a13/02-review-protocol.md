# Review: 01 - Codex Hook Wire Protocol

**Reviewer:** Cursor Agent (600f2a13)
**Plan doc:** `docs/plans/codex-integration/01-protocol.md`
**Review date:** 2026-05-10

## Verdict

APPROVE WITH COMMENTS

## Summary

The Codex hook wire format is mostly accurate against the current public Codex documentation: empty stdout for no objection, a deny envelope for `PreToolUse` blocks, and no supported `ask` decision in `PreToolUse`. The doc needs to resolve session precedence, specify permit0's fail-closed behavior for internal errors, and account for the current remote permission string mismatch.

## Detailed Findings

### Finding 1: Session ID priority contradicts the sample implementation

**Severity:** Major
**Location:** Session ID Extraction
**Claim:** Codex stdin `session_id` is priority 1, `CODEX_THREAD_ID` is priority 2, and `--session-id` is priority 3.
**Reality:** The sample implementation immediately below the list gives explicit `--session-id` priority over stdin and env values. The existing Claude helper also treats the explicit flag as priority one in `crates/permit0-cli/src/cmd/hook.rs:247-258`.
**Recommendation:** Choose one order. Prefer explicit `--session-id` first as an operator override, then Codex stdin `session_id`, then `CODEX_THREAD_ID`, then the existing fallback.

### Finding 2: The protocol should define Codex fail-closed output for internal permit0 errors

**Severity:** Major
**Location:** Error Handling
**Claim:** The doc says Codex fails open on invalid JSON, non-zero errors, timeout, crash, or malformed output.
**Reality:** That Codex behavior is accurate, but the doc does not define what permit0 must emit when it encounters its own errors. The current hook uses `?` for parsing, engine construction, evaluation, and serialization in `crates/permit0-cli/src/cmd/hook.rs:491-498`, `crates/permit0-cli/src/cmd/hook.rs:544-583`, and `crates/permit0-cli/src/cmd/hook.rs:671-672`, bubbling errors to `main()` in `crates/permit0-cli/src/main.rs:210-277`.
**Recommendation:** Add a protocol-level rule: in Codex mode, every recoverable permit0 error after process start must emit either a valid deny envelope or exit code 2 with a reason.

### Finding 3: Remote HITL wire values do not currently agree

**Severity:** Major
**Location:** Verdict Mapping Table
**Claim:** The remote daemon can be used as-is and the hook maps `HumanInTheLoop` to Codex deny.
**Reality:** The daemon serializes permissions as `result.permission.to_string().to_lowercase()` in `crates/permit0-cli/src/cmd/serve.rs:577-589`. `Permission::HumanInTheLoop` displays as `HUMAN` in `crates/permit0-types/src/permission.rs:13-18`, so remote JSON uses `"human"`. The current hook remote mapper matches `"humanintheloop"` only in `crates/permit0-cli/src/cmd/hook.rs:315-337`.
**Recommendation:** Document `"human"` as the daemon HITL wire value or change the daemon/hook contract, then update both the implementation and tests.

## Verified Claims

- Codex hooks use `session_id`, `turn_id`, `tool_name`, `tool_use_id`, and `tool_input` fields for `PreToolUse`, matching the public Codex hooks docs.
- Codex docs confirm empty stdout with exit code 0 means success/no objection.
- Codex docs confirm `permissionDecision: "allow"` and `"ask"` are parsed but unsupported for `PreToolUse`, and fail open.
- Codex docs confirm a `hookSpecificOutput` envelope with `hookEventName: "PreToolUse"` and `permissionDecision: "deny"` is the supported block shape.
- Codex docs confirm the legacy `{"decision":"block","reason":"..."}` shape and exit code 2 with stderr are accepted block paths.
- The MCP prefix shape `mcp__<server>__<tool>` matches the current Claude Code stripping implementation in `crates/permit0-cli/src/cmd/hook.rs:73-80`.
- The future `PermissionRequest` examples match the current Codex docs' `decision.behavior` shape for `allow` and `deny`.

## Questions for the Author

1. Should Codex mode use exit code 2 for internal errors instead of stdout JSON?
2. Should Codex metadata fields be preserved in `RawToolCall.metadata` in local mode for audit correlation?
