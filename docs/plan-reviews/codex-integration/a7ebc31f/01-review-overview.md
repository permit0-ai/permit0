# Review: 00 — Codex CLI Integration: Overview and Architecture

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/00-overview.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The overview correctly frames Codex as a near-replica of the Claude Code
hook adapter, and the data-flow diagram and comparison table are accurate
in their broad strokes. However, the doc lists "Maintain session context
for cross-call pattern detection" as a v1 goal and simultaneously claims
no daemon changes are needed — these two claims are contradictory under
`--remote` mode because the existing remote POST body strips session
metadata. The "no daemon changes" claim is also misleading because the
plan modifies `ClientKind`, which is shared between the hook adapter and
the daemon.

## Detailed Findings

### Finding 1: v1 goal #5 is unachievable with the proposed changes

**Severity:** Major
**Location:** "Scope > v1" bullet 5 ("Maintain session context for
cross-call pattern detection")
**Claim:** v1 supports session-aware mode in both local and remote modes.
**Reality:** In local mode, session-awareness works because the hook
opens a SQLite session store directly (verified at
`crates/permit0-cli/src/cmd/hook.rs:548-573`). In remote mode,
`evaluate_remote_with_meta` POSTs only `{tool_name, parameters}`
(`crates/permit0-cli/src/cmd/hook.rs:440-444`) — the Codex `session_id`
parsed from stdin is dropped on the floor. The daemon then either
operates statelessly or invents a fresh session per request (see
`crates/permit0-cli/src/cmd/serve.rs:130-134`). This contradicts the
plan's own admission in `05-limitations.md` Section 7 ("Remote Mode
Session Continuity") that this is deferred to v2.
**Recommendation:** Either (a) move "session context in remote mode" out
of v1 scope and align with `05-limitations.md`, or (b) add an explicit
implementation step to forward `metadata.session_id` (and
`client_kind: "codex"`) in the remote POST body, mirroring the OpenClaw
TS client at
`integrations/permit0-openclaw/src/Permit0Client.ts:155-163`.

### Finding 2: "No changes to daemon" claim is misleading

**Severity:** Major
**Location:** "Crate Dependencies" section ("permit0-cli (hook.rs)
<-- changes here", with engine/normalize/session/types marked "no
changes")
**Claim:** Only `hook.rs` and `main.rs` change; the daemon
(`serve.rs`) is unchanged.
**Reality:** `serve.rs` imports `ClientKind` from `hook.rs`
(`crates/permit0-cli/src/cmd/serve.rs:35`). Adding the new `Codex`
variant changes the daemon's behavior in a load-bearing way: it makes
`POST /api/v1/check` accept `"client_kind": "codex"` and apply the same
MCP prefix stripping. That's intentional and correct, but the plan
should call it out as a deliberate side-effect rather than denying
daemon changes exist. Otherwise reviewers will assume the daemon's
behavior is bit-identical.
**Recommendation:** Reword "Crate Dependencies" to: "permit0-cli
(hook.rs and serve.rs by transitive `ClientKind` import) — no other
crates touched." Add one line acknowledging that `client_kind: "codex"`
becomes valid in the daemon's `/api/v1/check` payload.

### Finding 3: Data-flow diagram omits the unknown-mode policy step

**Severity:** Minor
**Location:** "Data Flow" diagram, between steps 4 and 5
**Claim:** The hook (1) parses, (2) strips MCP prefix, (3) extracts
session_id, (4) builds RawToolCall, (5) maps Permission to Codex output.
**Reality:** Between engine evaluation and output mapping, the hook
runs `apply_unknown_policy` (`crates/permit0-cli/src/cmd/hook.rs:651`)
which can rewrite an `ask` verdict into `defer`/`allow`/`deny`. This is
documented in `02-implementation.md` "Unknown mode" subsection but the
overview's data-flow doesn't show it.
**Recommendation:** Add "5a. Apply --unknown policy (rewrites ask →
defer/allow/deny for unknown actions)" before the verdict-mapping step.

### Finding 4: "PermissionRequest" framing is ambiguous

**Severity:** Minor
**Location:** "Scope > Deferred to v2" bullet 1
**Claim:** PermissionRequest hook is a v2 feature.
**Reality:** The plan describes PermissionRequest in `01-protocol.md`
"PermissionRequest Hook (v2, Future)" and `05-limitations.md` "v2:
PermissionRequest Hook Integration", but doesn't disambiguate whether
PermissionRequest is (a) an existing Codex hook event the integration
chooses not to use yet, or (b) a Codex feature that doesn't exist
today. The reader can't tell whether shipping v2 requires Codex changes
or just permit0 changes.
**Recommendation:** Add one sentence: "PermissionRequest is an
existing Codex hook event since version <X.Y>; v1 of permit0
intentionally does not subscribe to it." Or, if it's planned-but-
not-yet-shipped, say so.

### Finding 5: Comparison-table HITL row understates the regression

**Severity:** Minor
**Location:** "Comparison with Claude Code Integration" table, row
"Ask/HITL verdict"
**Claim:** "Map to deny with informative reason"
**Reality:** This is technically what happens, but the user-visible
difference is significant: in Claude Code, an `ask` verdict yields a
prompt the user can approve in-band; in Codex v1, the same risk level
hard-blocks and the user must go elsewhere (allowlist, dashboard) to
unblock. The 05-limitations doc captures this but the overview
table makes it sound like a footnote.
**Recommendation:** Add a footnote or column on the table: "This is a
behavior regression for v1 Codex users — see 05-limitations.md §1."

## Verified Claims

- The reference hook (`crates/permit0-cli/src/cmd/hook.rs`) does
  intercept tool calls via `PreToolUse` stdin and writes a JSON envelope
  on stdout (verified end-to-end: lines 491–675).
- `RawToolCall` is the engine's input type (`crates/permit0-types/src/tool_call.rs:7-16`)
  and the hook constructs it from stdin parameters (`hook.rs:502-506`).
- The same `mcp__<server>__<tool>` stripping logic can be reused for
  Codex without modification (`hook.rs:74-92`, tested at lines 979–994).
- The engine (`permit0-engine`), normalizer registry, packs, and
  scoring config are all client-agnostic — searched for `ClientKind`
  references and confirmed they appear only in `hook.rs`, `serve.rs`,
  and `main.rs`.
- Packs at `packs/permit0/email/` contain no client-specific or
  vendor-specific gating; `pack.yaml` and risk_rules YAMLs operate on
  normalized actions only. The plan's claim "no pack changes" holds.
- `Permission::HumanInTheLoop` exists as a variant
  (`crates/permit0-types/src/permission.rs:9`).

## Questions for the Author

1. Does the v1 scope intentionally include "remote-mode session
   context"? If yes, where in `02-implementation.md` is the remote POST
   body change specified? If no, the v1 bullet list should be tightened.
2. Should the plan document explicitly acknowledge that adding `Codex`
   to `ClientKind` makes the daemon accept `"client_kind": "codex"`
   without further serve.rs changes (transitive import), so reviewers
   can verify the side-effect?
3. The diagram step "Strip MCP prefix" implies stripping happens before
   normalization. Is there a reason normalization couldn't be pushed
   server-side via `client_kind: "codex"` in the remote POST (matching
   OpenClaw)? That would centralize stripping and remove a divergence
   point.
