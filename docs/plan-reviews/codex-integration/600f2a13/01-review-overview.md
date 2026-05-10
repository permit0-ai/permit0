# Review: 00 - Codex CLI Integration: Overview and Architecture

**Reviewer:** Cursor Agent (600f2a13)
**Plan doc:** `docs/plans/codex-integration/00-overview.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The overview correctly uses the Claude Code hook adapter as the reference and scopes the first implementation toward hook I/O. It overstates parity in remote/session mode and in "same governance" claims, because the current remote path drops session metadata and the loaded packs do not cover every Codex tool the hook can intercept.

## Detailed Findings

### Finding 1: Remote session-aware parity is not supported by current code

**Severity:** Major
**Location:** Goal, Scope, Crate Dependencies
**Claim:** The Codex integration will maintain session context, work in remote mode, and provide the same session detection without daemon/session changes.
**Reality:** The hook remote helper posts only `tool_name` and `parameters` in `crates/permit0-cli/src/cmd/hook.rs:435-443`. The daemon can read `metadata.session_id`, but only constructs `SessionContext::new(sid)` in `crates/permit0-cli/src/cmd/serve.rs:130-134`; it does not load action history. Local session history is a separate `SqliteSessionStore` flow in `crates/permit0-cli/src/cmd/hook.rs:547-607`.
**Recommendation:** Either remove remote session-aware parity from v1, or add v1 work to forward Codex metadata and persist/replay daemon-side session records.

### Finding 2: "Same governance" is broader than the current pack surface

**Severity:** Major
**Location:** Goal, Scope
**Claim:** The integration provides the same governance for every intercepted Codex tool call.
**Reality:** The reference pack in this checkout is email-focused: `packs/permit0/email/pack.yaml:31-62` lists email action types and Gmail/Outlook channels. Unknown tools normalize to `unknown.unclassified`, and the default hook policy is `UnknownMode::Defer` in `crates/permit0-cli/src/cmd/hook.rs:122-140`. There is no Bash pack YAML in the loaded pack tree.
**Recommendation:** Say v1 governance applies to pack-covered actions plus the configured `--unknown` policy. If Bash/apply_patch governance is part of the product promise, add or reference those packs.

### Finding 3: The overview's "daemon as-is" claim misses an existing remote HITL mismatch

**Severity:** Major
**Location:** Crate Dependencies
**Claim:** The daemon's `POST /api/v1/check` endpoint is used as-is for `--remote` mode.
**Reality:** The endpoint exists, but the current CLI hook remote parser expects `"humanintheloop"` in `crates/permit0-cli/src/cmd/hook.rs:315-337`, while the daemon serializes `Permission::HumanInTheLoop` via `to_string().to_lowercase()` in `crates/permit0-cli/src/cmd/serve.rs:577-589`. `Permission::HumanInTheLoop` displays as `HUMAN` in `crates/permit0-types/src/permission.rs:13-18`, so the wire value is `"human"`.
**Recommendation:** Add a v1 fix to recognize `"human"` in the hook remote mapping, and add a test that pins the actual `serve.rs` response shape.

## Verified Claims

- `permit0 hook` is implemented in `crates/permit0-cli/src/cmd/hook.rs`, and the current module is a Claude Code `PreToolUse` hook adapter.
- `ClientKind::ClaudeCode` strips `mcp__<server>__<tool>` to the bare tool name in `crates/permit0-cli/src/cmd/hook.rs:73-80`.
- The hook reads stdin, parses `HookInput`, builds a `RawToolCall`, and routes through `engine.get_permission()` in `crates/permit0-cli/src/cmd/hook.rs:491-583`.
- Local mode supports optional SQLite-backed session history through `--db` in `crates/permit0-cli/src/cmd/hook.rs:547-607`.
- Remote mode delegates to `POST /api/v1/check` via `evaluate_remote_with_meta` in `crates/permit0-cli/src/cmd/hook.rs:435-468`.
- The daemon exposes `POST /api/v1/check` and returns permission/action/score fields in `crates/permit0-cli/src/cmd/serve.rs:53-96`.
- Codex's public hooks docs confirm `PreToolUse`, `PermissionRequest`, and `PostToolUse` exist, and that `PreToolUse` can intercept Bash, `apply_patch`, and MCP tool calls.

## Questions for the Author

1. Is remote session continuity required for v1, or should v1 remote mode be documented as stateless for session-history scoring?
2. Should v1 claim governance over Codex built-ins like Bash and `apply_patch`, or only over pack-backed MCP/email calls?
3. Should fixing the existing remote `"human"` vs `"humanintheloop"` mismatch be a prerequisite before adding Codex remote mode?
