# Review: 05 - Known Limitations and Future Work

**Reviewer:** Cursor Agent (600f2a13)
**Plan doc:** `docs/plans/codex-integration/05-limitations.md`
**Review date:** 2026-05-10

## Verdict

APPROVE WITH COMMENTS

## Summary

This doc captures Codex's most important hook limitations accurately: no native `ask` in `PreToolUse`, unsupported `allow`, incomplete `unified_exec` interception, limited non-shell/non-MCP coverage, and concurrent hooks. It needs to be reconciled with the earlier docs on remote session continuity, and it should distinguish post-execution audit enrichment from permit0's existing decision audit.

## Detailed Findings

### Finding 1: Remote session continuity contradicts earlier v1 scope

**Severity:** Major
**Location:** Remote Mode Session Continuity, Future Work
**Claim:** Remote session continuity is a limitation/future enhancement because the hook does not forward Codex `session_id`.
**Reality:** This limitation is accurate for current code: the hook remote POST body omits metadata in `crates/permit0-cli/src/cmd/hook.rs:435-443`, and the daemon only creates an empty `SessionContext` when metadata is present in `crates/permit0-cli/src/cmd/serve.rs:130-134`. But `00-overview.md` and `03-configuration.md` present remote session-aware mode as v1 behavior.
**Recommendation:** Keep this limitation and update the earlier docs, or move metadata forwarding plus daemon-side session history into v1 and remove this from limitations.

### Finding 2: PostToolUse audit wording implies v1 lacks audit

**Severity:** Minor
**Location:** v2: PostToolUse Hook for Audit
**Claim:** `PostToolUse` enables recording completed actions in the audit trail.
**Reality:** The engine already has decision audit support, and the daemon wires an audit sink in UI mode in `crates/permit0-cli/src/cmd/serve.rs:608-623`. What Codex `PostToolUse` would add is execution-result context after side effects occur: tool response, exit status, and anomalous output.
**Recommendation:** Reword this as "execution-result audit enrichment" or "post-execution audit" so it does not imply v1 lacks decision auditing.

## Verified Claims

- Codex docs confirm `PreToolUse` does not support `permissionDecision: "ask"` and unsupported `ask` fails open.
- Codex docs confirm `permissionDecision: "allow"` is parsed but unsupported for `PreToolUse` and fails open.
- Codex docs confirm `PreToolUse` does not intercept all shell paths and calls out incomplete `unified_exec` coverage.
- Codex docs confirm `PreToolUse` does not intercept `WebSearch` or other non-shell/non-MCP tools.
- Codex docs confirm multiple matching hooks run concurrently and one hook cannot prevent another matching hook from starting.
- Codex docs confirm `PermissionRequest` supports `decision.behavior = "allow"` and `"deny"`, and can decline to decide by returning no decision.
- Codex docs confirm `PostToolUse` exists but cannot undo already-completed side effects.
- The current permit0 daemon has `/api/v1/audit/replay` and audit sink plumbing, but it is separate from Codex `PostToolUse` in `crates/permit0-cli/src/cmd/serve.rs:182-331`.

## Questions for the Author

1. Should remote metadata forwarding be v2 rather than v3, since the daemon request schema already supports metadata?
2. Should this limitations doc include a short security posture statement that Codex v1 is a guardrail, not a complete enforcement boundary?
