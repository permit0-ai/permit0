# Code Review: Codex CLI Integration

**Reviewer:** Cursor Agent (EA49D626)
**Review date:** 2026-05-10
**Plan:** `docs/plans/codex-integration/`
**Files reviewed:**

- `crates/permit0-cli/src/cmd/hook.rs` (full file, including new code and unchanged regions)
- `crates/permit0-cli/src/cmd/serve.rs` (lines 1-170, plus prior reads of 560-590 and 240-280)
- `crates/permit0-cli/src/main.rs` (full Hook subcommand definition)
- `crates/permit0-cli/tests/cli_tests.rs` (full file)
- `crates/permit0-store/src/audit/redactor.rs` (full file)
- `crates/permit0-engine/src/engine.rs` (relevant audit / metadata flow regions)
- `crates/permit0-types/src/tool_call.rs` (RawToolCall struct)
- `crates/permit0-types/src/permission.rs` (Permission Display impl)
- `docs/plans/codex-integration/00-overview.md` through `05-limitations.md`
- `docs/plan-reviews/codex-integration/600f2a13/` and `a7ebc31f/` review folders

## Verdict

**APPROVE WITH COMMENTS**

The implementation correctly delivers the v1 Codex integration described in
the plan, including the critical fail-closed semantics that the prior plan
reviews flagged as the most likely failure mode. The findings below are all
quality / completeness issues — none would cause Codex to fail open in
practice, and none block merge. The Major finding (F1) is a pre-existing
code smell whose blast radius the change widens; it should be addressed in
a small follow-up.

## Executive Summary

This change adds a `Codex` `ClientKind` variant, an `OutputFormat` enum,
expanded `HookInput` Codex fields, a `hook_output_to_codex` emitter, a
`derive_session_id_for_format` helper, a `build_tool_call_metadata`
forwarder, and a fail-closed `run()` wrapper that converts any inner
error into a structured Codex deny envelope. It also fixes the latent
`"humanintheloop"` vs `"human"` wire-format mismatch in the remote-mode
mapper. All 80 unit tests and 21 integration tests pass; clippy is clean
with `-D warnings` on default members; the existing Claude Code,
ClaudeDesktop, OpenClaw, and Raw paths are byte-identical to before.
The implementation is well-tested at both the unit level (per-helper
behavior) and the process boundary (end-to-end binary invocations that
verify the security-critical "never emit `permissionDecision: \"allow\"`"
invariant).

## Findings

### F1: `_ => HookOutput::allow()` fallback widens fail-open blast radius for Codex

**Severity:** Major
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 962-967)
**Issue:** The intermediate `decision_label` match has a wildcard arm
that falls back to `HookOutput::allow()` "// unreachable, but
defensible". For Claude Code this is benign (allow envelope = tool runs
unprompted); for Codex it converts to **empty stdout = no objection =
tool runs unblocked**. The arm is structurally unreachable today
because `decision_label` is set from an exhaustive match on
`Permission` immediately above (lines 933-956), but the comment
"unreachable, but defensible" is the wrong direction of defense — a
truly defensive default for a fail-closed governance system is `deny`,
not `allow`. The change adds Codex to the formats this fallback feeds,
so any future regression that lets a non-`{allow,deny,ask}` label leak
into this match silently bypasses governance under Codex.
**Evidence:**

```962:967:crates/permit0-cli/src/cmd/hook.rs
    let base_output = match decision_label {
        "allow" => HookOutput::allow(),
        "deny" => HookOutput::deny(reason),
        "ask" => HookOutput::ask(reason),
        _ => HookOutput::allow(), // unreachable, but defensible
    };
```

**Recommendation:** Either (a) fold the two matches together by
matching directly on `result.permission` and skipping the
`decision_label` intermediate (which makes the compiler enforce
exhaustiveness), or (b) change the fallback to
`HookOutput::deny("permit0: unexpected verdict label")` so the
fail-closed invariant holds even under future variant additions. The
Codex `hook_output_to_codex_unknown_decision_label_fails_closed` test
already pins the same defensive contract for the emit boundary; the
build boundary should match.

### F2: Remote mode discards Codex audit metadata

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 818-824, 697-731)
**Issue:** `build_tool_call_metadata(&hook_input)` populates
`tool_call.metadata` with Codex stdin context (session_id, turn_id,
cwd, model, etc.) for forensic audit. In **local** mode this metadata
flows through the engine into `AuditEntry.raw_tool_call.metadata` and
is visible to dashboard / audit-log consumers. In **remote** mode,
`evaluate_remote_with_meta` POSTs only `{tool_name, parameters}` —
the metadata is silently dropped:

```701:705:crates/permit0-cli/src/cmd/hook.rs
    let body = serde_json::json!({
        "tool_name": tool_call.tool_name,
        "parameters": tool_call.parameters,
    });
```

So the metadata helper does work that's wasted in `--remote` mode.
This is consistent with `05-limitations.md` Section 7 ("Remote Mode
Session Continuity is v2"), but the implementation builds metadata it
cannot use.
**Recommendation:** Document the asymmetry inline in
`build_tool_call_metadata`'s rustdoc (e.g. "Local mode only; remote
mode does not forward metadata to the daemon — see `05-limitations.md`
Section 7"). A v2 follow-up that forwards `metadata` and `client_kind`
in the POST body is already planned and would close this gap.

### F3: Module-level doc still describes only Claude Code

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 1-26)
**Issue:** The module doc comment opens with "Claude Code PreToolUse
hook adapter" and only describes Claude Code's wire format. It also
shows the deprecated `{decision: "allow"}` shape (which Claude Code
silently ignores today). After this change, the module supports five
clients across two output formats. New code readers will form the
wrong mental model.
**Recommendation:** Update the doc header to "PreToolUse hook adapter
for Claude Code, Claude Desktop, OpenClaw, Codex, and Raw clients,"
mention `OutputFormat`, and replace the legacy `{decision}` example
with a current `hookSpecificOutput` envelope. Add a short "Codex
fail-closed semantics" subsection mirroring the docstring on `run()`.

### F4: `Hook` subcommand help text is stale

**Severity:** Minor
**File:** `crates/permit0-cli/src/main.rs` (lines 37, 48, 67-69, 86-87)
**Issue:** Several help strings still describe Claude-Code-only
behavior:

- Line 37: `/// Claude Code PreToolUse hook adapter (reads JSON from stdin)`
- Line 48: `/// Session ID (default: derived from CLAUDE_SESSION_ID or PPID)` — no mention of `CODEX_THREAD_ID`.
- Lines 67-69: `--remote` help says the hook "translates the response into the Claude Code hookSpecificOutput envelope" — for `--client codex` it actually translates into a Codex envelope or empty stdout.
- Lines 86-87: `--unknown defer` help says "Claude Code's own permission flow handles it" — for Codex, defer means "Codex sees no objection."

**Recommendation:** Update each string to be format-neutral. E.g.
"Session ID (default: derived from `--client`-specific source —
`CLAUDE_SESSION_ID` or stdin `session_id` for Codex — falling back to
PPID)." The `--client` help text was correctly updated in this PR;
these other fields should follow.

### F5: `UnknownMode` variant docstrings are inaccurate for Codex

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 169-186)
**Issue:** Variant docs describe Claude-shaped wire output:

- `UnknownMode::Ask`: "Emit `permissionDecision: \"ask\"` with permit0's reasoning. The user is prompted via Claude Code's UI before the tool runs."
- `UnknownMode::Allow`: "Emit `permissionDecision: \"allow\"` — the tool runs unprompted."
- `UnknownMode::Defer`: "Emit a hook output with **no** `permissionDecision`, letting Claude Code's own permission flow take over."

For Codex, `Ask` is mapped to a deny envelope; `Allow` produces
empty stdout (the literal `permissionDecision: "allow"` is forbidden
under Codex per the protocol); `Defer` is also empty stdout. The
high-level intent ("prompt", "let it run", "no opinion") is
preserved across formats, but the wire-shape claims are wrong for
Codex.
**Recommendation:** Reword to be format-neutral, e.g.
`UnknownMode::Allow`: "Let the tool run unprompted (Claude Code:
`allow` envelope; Codex: empty stdout)." This pairs with the F3
update.

### F6: Outer `eprintln!` log prefix differs from inner shadow logs

**Severity:** Nit
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 778, 845-852, 977-985)
**Issue:** The Codex fail-closed wrapper logs as
`"permit0 codex hook error: …"`. Other stderr breadcrumbs use
`"[permit0 shadow] WOULD …"` or `"permit0: …"`. Operators grepping
logs benefit from a consistent prefix.
**Recommendation:** Use a uniform `"permit0:"` prefix
(`"permit0: codex hook error: {e}"`). Cosmetic only.

### F7: `unused_must_use` in `eprintln` of background drain not relevant here, but `read_to_string` swallows EOF zero-byte case

**Severity:** Nit
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 805-811)
**Issue:** If Codex (or any client) closes stdin with zero bytes
written, `serde_json::from_str("")` returns an `Err` ("EOF while
parsing a value"). Under Codex this correctly fails closed (deny
envelope) via the outer wrapper. Under Claude Code, this returns
non-zero exit (Claude prompts the user). Both behaviors are
acceptable, but no test exercises the empty-stdin case explicitly.
**Recommendation:** Add a `codex_hook_empty_stdin_fails_closed`
integration test mirroring `codex_hook_malformed_stdin_fails_closed`
but with zero-byte stdin. Optional defensive coverage; not a bug.

## Systemic Assessment

### Architectural Fit

The change respects existing crate boundaries cleanly. All the new
code lives in the CLI hook adapter (`crates/permit0-cli/src/cmd/hook.rs`)
and minimal CLI dispatch help text in `main.rs`. The engine, scoring,
normalize, packs, profiles, and store crates are untouched, matching
the plan's "Files NOT Changed" claim. The `OutputFormat` abstraction
slots correctly between the existing `ClientKind` (input prefix
identity) and the wire-output boundary; it's the right factoring and
the exhaustive `from_client` match makes future additions deliberate.
The transitive daemon impact (`serve.rs` gains
`client_kind: "codex"` support via the shared `ClientKind` import) is
correct — the daemon stays format-agnostic and just hands JSON back to
the hook, which knows how to emit per format. No layer-skip violations.

### Security

The change strengthens the fail-closed invariant for Codex via a
deliberate top-level error wrapper that catches every recoverable
failure from `run_inner` and converts it into a structured deny
envelope. The implementation prevents the most dangerous Codex
failure modes — non-zero exit, malformed stdout, transport errors,
remote daemon down, unknown decision labels — all from leaking out
as silent allow. The `hook_output_to_codex_never_emits_allow_decision`
unit test plus the `codex_hook_never_emits_permission_decision_allow`
integration test enforce the structural "must not emit allow envelope"
invariant across the Codex format paths most likely to regress.
The pre-existing redactor in `permit0-store::audit::redactor` walks
`RawToolCall.metadata` recursively; its FIELD_PATTERNS (password,
secret, token, api_key, authorization, credential, ssn, dob, mrn,
private_key) and VALUE_PATTERNS (Bearer, sk_live_, ghp_, JWT, etc.)
do not match my new metadata keys (session_id, turn_id, cwd,
hook_event_name, model, tool_use_id, transcript_path) or their typical
values (UUIDs, paths, model slugs), so audit metadata enrichment does
not interact poorly with redaction.

The one remaining sharp edge is F1: a `_ => HookOutput::allow()`
fallback that should be a deny for fail-closed completeness. It is
structurally unreachable today, but gets read by Codex now, so
hardening it is prudent.

### Backward Compatibility

Existing Claude Code, Claude Desktop, OpenClaw, and Raw paths are
byte-identical:

- `OutputFormat::from_client` maps every existing variant to
  `ClaudeCode` (verified by `output_format_from_client` test).
- `emit_hook_output(ClaudeCode, …)` calls `serde_json::to_string`
  on the same `HookOutput` shape and emits the same envelope.
- `HookInput`'s new fields all carry `#[serde(default)]`, so
  Claude Code's minimal `{tool_name, tool_input}` payload deserializes
  with all Codex fields as `None` (verified by
  `hook_input_claude_code_compat`).
- `build_tool_call_metadata` returns an empty map for Claude Code
  payloads (verified by
  `build_tool_call_metadata_claude_payload_is_empty`), so audit
  records and the daemon `extract_string_field("session_id")` lookup
  are unchanged for Claude.
- The prerequisite `"human"` recognition is additive: existing
  `"humanintheloop"` arm is preserved, the new test
  `remote_response_human_maps_to_ask` pins the canonical daemon
  value, and the misnamed
  `remote_response_parses_real_check_response_shape` test (which
  pinned `"humanintheloop"`) was left intact per the engineering
  skill's "do not change existing test assertions."
- The `--client codex` value is additive on the CLI; existing
  invocations without `--client` continue to default to Claude Code.

### Testing Coverage

Unit coverage (in `hook.rs`, 80 tests total) is comprehensive:

- ClientKind parsing, including case-sensitivity contract pinning.
- MCP prefix stripping for the new variant, including the
  hyphen-to-underscore Codex sanitization edge case.
- Full Codex stdin payload deserialization, plus null and
  empty-string handling.
- All four `apply_unknown_policy` modes × Codex emitter combinations.
- Round-trip through `hook_output_to_codex` for every
  `HookOutput` constructor, including the structural invariant test
  for `permissionDecision: "allow"` non-emission.
- The defensive "unknown decision label" fail-closed test for the
  emitter.
- Daemon `"human"` wire-format pin (the prerequisite fix).
- JSON escape safety on the deny envelope.
- Session-ID derivation: stdin priority, explicit override, empty
  string fallthrough, Claude format ignoring stdin.
- Metadata helper: full Codex payload, Claude minimal (empty),
  empty-string drop.

Integration coverage (in `cli_tests.rs`, 7 new tests) hits the
process boundary where Codex's fail-open semantics live:

- Empty stdout for unknown defer and shadow paths (zero-byte
  invariant).
- Deny envelope for `--unknown deny` and remote-daemon-down.
- Fail-closed handling of malformed stdin.
- Back-compat with minimal Claude payload under `--client codex`.
- Multi-mode "never emits permissionDecision: allow" structural
  check.

Gap (Nit, F7): no explicit zero-byte stdin test. Optional. The
existing test matrix is otherwise tight.

## What Was Done Well

- The fail-closed Codex wrapper at the top of `run()` is the
  right place to put it, and the comment block explaining why
  non-zero exits and malformed stdout fail open in Codex is clear
  enough that a future reader will not "simplify" it.
- `hook_output_to_codex` operates on the same `HookOutput` shape
  the rest of the pipeline already uses (unknown policy, remote
  response, remote error, shadow). This avoids the
  `codex_output(Permission, reason)` design that the prior plan
  reviews (`a7ebc31f` finding 1, `600f2a13` finding 2) flagged as
  too narrow. The factoring respects the existing decision model.
- The prerequisite fix for `"human"` vs `"humanintheloop"` is
  scoped to a single match-arm change plus two new pinning tests,
  with the existing test left intact. This is the right
  blast-radius minimization.
- `build_tool_call_metadata` is a small, focused helper with a
  clear contract (drops empty strings, returns empty for non-Codex
  payloads) and three unit tests covering the obvious branches.
  Forwarding stdin context into `metadata` rather than ignoring it
  pulls real audit value out of the change.
- `OutputFormat::from_client` uses an exhaustive match across all
  five `ClientKind` variants. Adding a future client now forces a
  conscious decision about which envelope it should emit. This
  matches the engineering skill's "Open/Closed" guidance.
- `derive_session_id_for_format` correctly handles the empty-string
  case (`stdin_session_id.filter(|s| !s.is_empty())`) — a subtle
  trap pointed out by reviewer `a7ebc31f` finding 4.
- The integration test file uses a structural JSON check (not
  substring matching) for the "never emits allow" invariant,
  matching reviewer `a7ebc31f` finding 1's recommendation.
- The codex deny envelope is built via `serde_json::json!` rather
  than `format!`, so user-supplied reason strings with quotes /
  newlines / backslashes are correctly escaped — verified by
  `codex_deny_envelope_escapes_reason_text`.
- The `codex_output(Permission, &str)` helper is gated with
  `#[cfg(test)]` rather than a production `#[allow(dead_code)]`,
  matching the engineering skill's "no `allow(dead_code)`" rule.
- Test names describe behavior, not implementation
  (`codex_hook_unknown_defer_produces_empty_stdout`, not
  `test_defer`). Consistent with the project conventions.

## Verified Correctness

- [x] `ClientKind::Codex` strips `mcp__<server>__<tool>` identically
      to `ClientKind::ClaudeCode` — confirmed by the OR-pattern arm at
      `crates/permit0-cli/src/cmd/hook.rs:83-86` and by
      `codex_strips_mcp_double_underscore_prefix` (line 1646).
- [x] `OutputFormat::from_client` is exhaustive (no `_` arm) —
      confirmed at `crates/permit0-cli/src/cmd/hook.rs:145-153`.
- [x] `HookInput` deserializes Claude minimal payloads with all
      Codex fields as `None` — confirmed by `hook_input_claude_code_compat`
      at `crates/permit0-cli/src/cmd/hook.rs:1731-1747`.
- [x] `HookInput` deserializes the full Codex payload, including
      `null` `transcript_path` — confirmed by
      `codex_hook_input_full_payload` (line 1697) and
      `hook_input_codex_null_transcript_path` (line 1834).
- [x] `codex_deny_envelope` produces JSON with the exact required
      `hookSpecificOutput` / `hookEventName` / `permissionDecision` /
      `permissionDecisionReason` shape — confirmed by
      `codex_output_deny_produces_envelope` and
      `codex_deny_envelope_escapes_reason_text`.
- [x] `hook_output_to_codex` returns `None` for `Some("allow")` and
      `None` (defer) — confirmed at lines 393-394 and tests at 1903-1914.
- [x] `hook_output_to_codex` maps `Some("ask")` to a deny envelope
      with HITL-aware fallback reason — confirmed at lines 402-408
      and `hook_output_to_codex_ask_maps_to_deny`.
- [x] `hook_output_to_codex` fails closed for unknown decision labels
      — confirmed by `hook_output_to_codex_unknown_decision_label_fails_closed`
      (line 1963).
- [x] `emit_hook_output(Codex, &HookOutput::allow())` writes zero
      bytes to stdout — confirmed by the conditional in lines 427-431
      and end-to-end by `codex_hook_unknown_defer_produces_empty_stdout`
      and `codex_hook_shadow_produces_empty_stdout`.
- [x] `emit_hook_output` does not call `println!("")` for the Codex
      empty-stdout case (no trailing newline) — confirmed by
      `output.stdout.is_empty()` assertions in integration tests.
- [x] `derive_session_id_for_format(Codex, …)` priority order is
      explicit > stdin > `CODEX_THREAD_ID` > legacy
      `derive_session_id` — confirmed at lines 521-538 and four
      dedicated tests.
- [x] `build_tool_call_metadata` drops empty strings — confirmed by
      `build_tool_call_metadata_drops_empty_strings`.
- [x] The audit redactor (`permit0-store::audit::redactor::FIELD_PATTERNS`)
      does not match any of my new metadata keys (session_id, turn_id,
      cwd, hook_event_name, model, tool_use_id, transcript_path) —
      verified by inspecting the patterns at
      `crates/permit0-store/src/audit/redactor.rs:19-35`.
- [x] `run()` Codex wrapper catches every `Err` from `run_inner` and
      emits a structured deny envelope — confirmed at lines 769-785
      and exercised end-to-end by
      `codex_hook_malformed_stdin_fails_closed` and
      `codex_hook_remote_daemon_down_fails_closed`.
- [x] Claude Code path still propagates `Err` for non-zero exit
      (existing behavior preserved) — confirmed at line 773
      (`(OutputFormat::ClaudeCode, Err(e)) => Err(e)`).
- [x] Daemon (`serve.rs:114-118`) accepts `client_kind: "codex"` via
      the shared `ClientKind::from_str` import — confirmed by reading
      `serve.rs` and the existing `check_request_accepts_client_kind`
      test that passes after my changes.
- [x] Prerequisite fix accepts both `"human"` and `"humanintheloop"`
      — confirmed at `remote_response_to_hook_output` lines 586 and
      `remote_response_human_maps_to_ask` (line 1524).
- [x] No `unwrap()` in non-test code other than `expect("...")` for
      structurally-guaranteed serialization in `codex_deny_envelope`.
- [x] No `#[allow(dead_code)]` introduced; `codex_output` is gated
      with `#[cfg(test)]` instead.
- [x] `cargo fmt --check -p permit0-cli` clean.
- [x] `cargo clippy --all-targets -- -D warnings` clean on default
      members (the workspace `--workspace` failure is environmental
      pyo3 / Python 3.14, not from this change).
- [x] `cargo test --all-targets` — 628 tests pass workspace-wide,
      including 80 unit tests in `permit0-cli::cmd::hook` and 21
      integration tests in `cli_tests.rs`. Pre-existing 3 calibration
      corpus failures reproduce on `main` without these changes —
      out of scope.
- [x] Plan fidelity: every numbered change in
      `docs/plans/codex-integration/02-implementation.md` is
      implemented; the Major and Critical findings from
      `docs/plan-reviews/codex-integration/600f2a13/` and `a7ebc31f/`
      were addressed during implementation (HookOutput-based emitter
      not `Permission`-based; client-neutral decision model; fail-closed
      wrapper; `"human"` matcher fix; format-aware shadow path).
