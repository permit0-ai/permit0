# Review: 05 — Known Limitations and Future Work

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/05-limitations.md`
**Review date:** 2026-05-10

## Verdict

APPROVE WITH COMMENTS

## Summary

This is the strongest doc in the set. The seven v1 limitations are
honest, the impact assessments are calibrated, and the v2/v3 future
work sketches are concrete enough to pick up later. The main issues
are (a) limitation #7 (Remote Mode Session Continuity) silently
contradicts `00-overview.md`'s v1 scope and `03-configuration.md`'s
session-aware-mode promise — these need to be reconciled rather than
left as latent contradictions, and (b) one major limitation is
missing: the latent `"humanintheloop"` vs `"human"` wire-format bug
the Codex remote path inherits.

## Detailed Findings

### Finding 1: Add a Section 8: latent HITL wire-format mismatch

**Severity:** Critical
**Location:** New section after "Section 7: Remote Mode Session Continuity"
**Claim:** None (limitation is missing).
**Reality:** As documented in `02-review-protocol.md` Finding 1 and
`03-review-implementation.md` Finding 1, the Codex remote path
inherits a pre-existing bug in `remote_response_to_hook_output`
(`crates/permit0-cli/src/cmd/hook.rs:317-336`): it expects
`"humanintheloop"` but the daemon emits `"human"`
(`crates/permit0-cli/src/cmd/serve.rs:578` + Display impl). For Codex
remote mode + HITL verdict, the user sees "permit0 remote: unknown
permission value 'human'" instead of the proper risk reason. This is
a v1 limitation OR a bug to be fixed in this PR. Either way it must
be acknowledged.
**Recommendation:** Add Section 8: "Remote-mode HITL deny reason is
mis-labelled (latent bug)". Spell out the symptom, the existing test
that masks it (`hook.rs:1183, 1231` use `"humanintheloop"` literals),
and the recommended fix (also accept `"human"` in the matcher,
update the affected tests).

### Finding 2: Section 7 (Session Continuity) contradicts v1 scope claims

**Severity:** Major
**Location:** Section 7, "v1 workaround" paragraph
**Claim:** "The daemon creates a fresh session context per request."
**Reality:** `00-overview.md` lists "Maintain session context for
cross-call pattern detection" as v1 scope. `03-configuration.md`
"Session-Aware Mode" subsection says "the Codex hook passes the
`session_id` from the stdin payload through to the daemon". Both
contradict Section 7 here. Either v1 supports remote-mode session
continuity (and Section 7 is wrong) or it doesn't (and the other two
docs are wrong). The limitations doc is correct — but the
contradiction must be fixed in the other docs.
**Recommendation:** No change to this doc — but flag the
contradiction in the cross-doc review (already captured in
`01-review-overview.md` Finding 1 and `04-review-configuration.md`
Finding 1). Add a one-line cross-reference here: "(Note: this
contradicts `00-overview.md` v1 scope bullet 5 — those docs need
correcting.)"

### Finding 3: Section 1 "v2 plan" understates complexity of HITL via PermissionRequest

**Severity:** Major
**Location:** Section 1 ("No Native HITL / Ask Verdict"), "v2 plan" paragraph
**Claim:** "Use the `PermissionRequest` hook (see below)."
**Reality:** The "v2: PermissionRequest Hook Integration" subsection
later describes the approach but glosses over a critical race: in
v1, `PreToolUse` returns deny immediately for HITL. In v2, the same
verdict would return exit-0 from `PreToolUse` (no objection), then
the call proceeds to Codex's approval prompt, then
`PermissionRequest` fires asking permit0 again. But
`PermissionRequest` is a separate subprocess invocation — it has no
access to the `PreToolUse` evaluation result. The proposal mentions
"Requires inter-hook state sharing (e.g., a shared temp file or
SQLite cache)" but doesn't address race conditions: between
`PreToolUse` writing the cache and `PermissionRequest` reading it,
the cache file must be visible to a different process. On macOS or
NFS this can have weird semantics. The plan should call out the race
concern as part of v2 design risk.
**Recommendation:** Add a sub-bullet under "Complexity": "Race
condition risk: PreToolUse must finish writing its cache entry
BEFORE PermissionRequest runs. Codex's hook scheduling (concurrent?
sequential?) needs verification. Use file-system locking or atomic
rename to avoid partial writes."

### Finding 4: Section 2's silent-bypass risk underspecifies the test

**Severity:** Minor
**Location:** Section 2 ("`permissionDecision: \"allow\"` Is Rejected"), "Risk" paragraph
**Claim:** "The test suite includes a specific test
(`codex_output_never_contains_allow`) to catch this at CI time."
**Reality:** As detailed in `05-review-testing.md` Finding 1, that
test only covers the `codex_output` function in isolation. It
doesn't catch shadow-mode or unknown-mode-rewrite paths that bypass
`codex_output`. So the limitations doc overstates the safety net.
**Recommendation:** Soften: "A test (`codex_output_never_contains_allow`)
catches the most common failure path. The shadow-mode path and the
unknown-mode-rewrite path are not yet covered — see Section 8 for
follow-up." (Or: extend the test as recommended in
`05-review-testing.md` and update this doc to reflect actual
coverage.)

### Finding 5: Section 6 (Multiple Hooks Cannot Coordinate) is correct but incomplete

**Severity:** Minor
**Location:** Section 6, "Impact" paragraph
**Claim:** "Any single deny result blocks the tool, so permit0's
deny still takes effect regardless of other hooks."
**Reality:** True for deny. But for HITL → deny mapping, if another
hook (e.g. a custom user hook) emits an exit-0 allow ENVELOPE for
the same call, and Codex prefers the explicit allow over the
permit0 deny, then permit0's deny might be overridden. The doc
should specify Codex's "any deny wins" semantics or note that this
is unverified.
**Recommendation:** Add: "Verified on Codex version <X>: any
single deny envelope from any hook wins. If this changes in a
future Codex version, permit0's deny could be silently overridden."
Or: "(Codex's hook-result combination semantics are documented at
[link]; we rely on 'any deny wins'.)"

### Finding 6: "v3 Codex Plugin Packaging" mentions PLUGIN_ROOT without context

**Severity:** Nit
**Location:** "v3: Codex Plugin Packaging" subsection
**Claim:** "PLUGIN_ROOT env var for portable paths"
**Reality:** Without prior reference, the reader doesn't know
whether `PLUGIN_ROOT` is a Codex convention or something permit0
would invent. Brief context would help.
**Recommendation:** Either link to Codex's plugin docs or note
"(per Codex plugin convention)". If PLUGIN_ROOT is not yet a
Codex feature, label it as "proposed".

### Finding 7: "v3 Codex Cloud Integration" assumes a sidecar pattern that may not be possible

**Severity:** Nit
**Location:** "v3: Codex Cloud Integration" subsection
**Claim:** "A sidecar daemon running alongside the agent container"
**Reality:** Codex Cloud (per OpenAI's public-facing docs) runs
agents in managed containers. Whether users can attach sidecars at
all is a Codex Cloud product decision, not a permit0 implementation
detail. The doc should mark this assumption explicitly so the v3
roadmap doesn't depend on it being true.
**Recommendation:** Add: "Assumes Codex Cloud allows user-injected
sidecars in agent containers — pending product verification."

## Verified Claims

- Section 1's claim that Codex `PreToolUse` lacks `permissionDecision: "ask"`
  is consistent with the protocol doc; both align on mapping HITL → deny.
- Section 2's claim that Codex rejects `permissionDecision: "allow"`
  is plausible (Claude Code historically had a similar restriction)
  but unverified against Codex source. The unit-test invariant
  approach is the right defensive posture regardless.
- Section 7's claim about the remote POST body containing only
  `tool_name` and `parameters` is verified at
  `crates/permit0-cli/src/cmd/hook.rs:440-444`.
- The OpenClaw integration's metadata-forwarding reference is
  accurate — `integrations/permit0-openclaw/src/Permit0Client.ts:155-163`
  builds metadata with `session_id` and `task_goal` and sets
  `client_kind: "openclaw"`. The v2 proposal aligns with this
  established pattern.
- Section 4 (WebSearch not intercepted) is consistent with how
  hooks-based interception works in similar systems; no permit0-side
  way to fix it.
- Section 6 (multiple hooks concurrent, no ordering) matches typical
  hook-system designs.

## Questions for the Author

1. Should the new "Section 8: HITL wire-format bug" (Finding 1) be a
   v1 limitation OR a fix-in-this-PR item? The latter would be
   strictly better for governance — Claude Code remote mode is
   currently broken on HITL too.
2. Section 7's v2 plan is concrete (forward `metadata.session_id`
   like OpenClaw does). Is there an estimate or commitment for v2 timing?
   If v2 is far out, the v1 docs need to be more explicit that
   Codex remote mode is "best for stateless governance, not session-aware".
3. For PermissionRequest v2 (Finding 3), is the proposed
   inter-hook cache (file-system or SQLite) something the existing
   `permit0-session` crate could provide, or does it need a new
   subsystem? Choosing now affects the v2 implementation surface.
4. Are there other "deferred" items not in this doc? E.g.,
   `unified_exec` interception is acknowledged as out-of-scope
   forever (Section 3), but the v3 list doesn't address it. Is it
   truly "never" or "wait for Codex to add hooks for it"?
