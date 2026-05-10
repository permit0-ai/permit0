# Plan Review Summary: codex-integration

**Reviewer:** Cursor Agent (600f2a13)
**Review date:** 2026-05-10
**Plan location:** `docs/plans/codex-integration/`

## Overall Verdict

REQUEST CHANGES

## Key Findings

- Critical: The implementation plan keeps the current `anyhow::Result` / `?` shape around parsing, engine setup, permission evaluation, remote calls, and output serialization. In Codex, those non-zero exits and malformed outputs fail open, so implementing the plan literally can silently bypass governance.
- Critical: The test plan does not exercise Codex's fail-open failure modes at the process boundary: malformed stdin, missing packs, remote daemon down, invalid stdout, HITL mapping, or accidental `permissionDecision: "allow"` from the full `run()` path.
- Major: The remote hook and daemon wire formats already disagree on HITL. `serve.rs` serializes `Permission::HumanInTheLoop` as `"human"`, while `hook.rs` only recognizes `"humanintheloop"`, so using `/api/v1/check` "as-is" produces confusing remote hook behavior.
- Major: The docs promise remote session-aware parity, but the hook remote POST body omits metadata and the daemon only creates an empty `SessionContext` from `metadata.session_id`; it does not persist or replay session history.
- Major: The proposed Codex output helper is too narrow because current hook behavior is expressed through Claude-shaped `HookOutput` values for unknown policy, remote responses, remote errors, and shadow mode.
- Major: The plan is inconsistent about Codex session precedence and remote metadata: one doc says stdin `session_id` is primary, the snippet gives `--session-id` priority, and the configuration guide says remote mode forwards session IDs while the limitations doc says it does not.

## Statistics

| Metric | Count |
|--------|-------|
| Plan docs reviewed | 6 |
| Critical findings | 2 |
| Major findings | 13 |
| Minor findings | 5 |
| Nits | 0 |
| Verified claims | 39 |
| Open questions | 12 |

## Recommendation

Do not implement from this plan as-is. The basic direction is right: Codex can be added at the CLI hook adapter boundary for local, pack-backed checks. But the plan needs an explicit Codex fail-closed error strategy, a client-neutral internal hook decision model, and a corrected remote HITL/session design before implementation.

The author should decide whether remote session continuity is in v1. If it is, v1 must forward metadata and add daemon-side session history. If not, the overview and configuration guide should describe remote mode as stateless for cross-call session detection.
