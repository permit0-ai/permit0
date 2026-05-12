# Code Review: Codex CLI Integration (`permit0 hook --client codex`)

**Reviewer:** Cursor Agent (1BFBB7EA)
**Review date:** 2026-05-10
**Plan:** `docs/plans/codex-integration/`
**Plan reviews referenced:** `docs/plan-reviews/codex-integration/600f2a13/`,
  `docs/plan-reviews/codex-integration/a7ebc31f/`
**Files reviewed:**
- `crates/permit0-cli/src/cmd/hook.rs` (full, 2133 lines)
- `crates/permit0-cli/src/cmd/serve.rs` (full, 889 lines)
- `crates/permit0-cli/src/main.rs` (full, 308 lines)
- `crates/permit0-cli/tests/cli_tests.rs` (full, 598 lines)
- `crates/permit0-cli/src/engine_factory.rs` (selected helpers)
- `crates/permit0-engine/src/engine.rs` (decision pipeline, ~lines 100–310)
- `crates/permit0-engine/src/context.rs` (`PermissionCtx`, `with_session`)
- `crates/permit0-types/src/permission.rs` (`Display` → `"HUMAN"`)
- `crates/permit0-types/src/taxonomy.rs` (`ActionType::UNKNOWN`, `Domain::Unknown`)
- `crates/permit0-types/src/tool_call.rs` (`RawToolCall.metadata`)
- `integrations/permit0-openclaw/src/Permit0Client.ts` (remote `metadata`
  conventions, for comparison)

## Verdict

**APPROVE WITH COMMENTS**

The implementation faithfully executes the revised plan, resolves every
critical and major finding raised in both plan reviews
(`600f2a13`, `a7ebc31f`), and ships strong test coverage at both the
unit and process level. The fail-closed wrapper, format-aware emit, and
end-of-pipeline `HookOutput` → Codex conversion are well-structured and
keep the Claude Code path untouched. No critical or major issues remain.
A small handful of minor UX, documentation, and test-coverage gaps are
called out below; none are merge blockers.

## Executive Summary

The Codex integration is implemented as a CLI-only change: a new
`ClientKind::Codex` variant plus an `OutputFormat::{ClaudeCode, Codex}`
enum that controls how a finalized `HookOutput` is serialized. By
converting at the very end of the pipeline (via `hook_output_to_codex`
and the `emit_hook_output` dispatch in `crates/permit0-cli/src/cmd/hook.rs`),
the implementation correctly reuses the existing
`apply_unknown_policy` / remote-response / remote-error / shadow
rewrites without duplication — the design refinement the plan reviewers
specifically asked for. The fail-closed wrapper in `run()` catches
every recoverable error from the inner pipeline and emits a deny
envelope, eliminating the "non-zero exit fails open" trap that the
`600f2a13` plan review flagged as critical. The HITL wire-format bug
the `a7ebc31f` plan review flagged (daemon emits `"human"`, hook only
recognized `"humanintheloop"`) is fixed by accepting both values in
`remote_response_to_hook_output` and is regression-locked by
`remote_response_parses_actual_daemon_human_shape`. End-to-end
integration tests cover the four most dangerous Codex failure modes
(malformed stdin, remote-down, shadow allow, never-emit-allow).

## Findings

### F1: HITL→deny reason text omits the "requires human review" hint

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 402–408, 586–592, 943–956)
**Issue:** When `Permission::HumanInTheLoop` is converted to a Codex
deny envelope, the reason text reads e.g.
`"permit0: email.send (gmail) — risk 62/100 High"`. There's no marker
telling the user that this is a Medium/High-tier action that *would
have* been routed to an approval prompt on Claude Code — Codex users
see a deny that looks identical in shape to a Critical-tier block.
`02-implementation.md` specifically called out that the reason should
include "— requires human review" plus an "Add to allowlist via
dashboard or re-run with approval" hint, exactly so this case is
distinguishable.

**Evidence:** Local path constructor at hook.rs:943-956 produces:

```943:956:crates/permit0-cli/src/cmd/hook.rs
        Permission::HumanInTheLoop => (
            "ask",
            format!(
                "permit0: {} ({}) — risk {}/100 {:?}",
                result.norm_action.action_type.as_action_str(),
                result.norm_action.channel,
                result.risk_score.as_ref().map_or(0, |s| s.score),
                result
                    .risk_score
                    .as_ref()
                    .map_or(permit0_types::Tier::Medium, |s| s.tier),
            ),
        ),
```

The Codex converter at hook.rs:402-408 just relays the existing reason
without prefixing the HITL semantics:

```402:408:crates/permit0-cli/src/cmd/hook.rs
        Some("ask") => Some(codex_deny_envelope(
            output
                .hook_specific_output
                .permission_decision_reason
                .as_deref()
                .unwrap_or("permit0: requires human review"),
        )),
```

**Recommendation:** In `hook_output_to_codex`'s `Some("ask")` arm,
prepend a stable marker (e.g. `"permit0 [HITL→deny]: "` or append
`" — requires human review"`) when transforming `ask` to `deny`. The
fallback string already includes "requires human review"; the same
phrase should appear when the input reason was non-empty. This keeps
the Claude Code path untouched (it never invokes this branch) and
distinguishes "blocked because critical" from "blocked because Codex
PreToolUse has no ask".

### F2: Stale module-level documentation on `hook.rs`

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 1–26)
**Issue:** The module docstring still reads "Claude Code PreToolUse
hook adapter" and only shows a Claude-flavored example
(`{ "decision": "allow" }`), which is also the *legacy* output shape
that the rest of the codebase has moved past (the current envelope is
`hookSpecificOutput.permissionDecision`). After this PR, the same
module also serves Codex and is the canonical adapter for OpenClaw and
Raw clients too.

**Evidence:**

```1:26:crates/permit0-cli/src/cmd/hook.rs
#![forbid(unsafe_code)]

//! Claude Code PreToolUse hook adapter.
//!
//! Claude Code invokes hooks with a JSON payload on stdin describing
//! the tool call. The hook responds with a JSON object:
//!
//! - `{ "decision": "allow" }` — permit the tool call
//! - `{ "decision": "block", "reason": "..." }` — deny the tool call
//! - `{ "decision": "ask_user", "message": "..." }` — human-in-the-loop
```

**Recommendation:** Replace the header with something like "PreToolUse
hook adapter for Claude Code, OpenAI Codex, and OpenClaw" and update
the example to the current `hookSpecificOutput` envelope. Mention that
the Codex path uses empty-stdout for allow and reuses the Claude
envelope shape with `permissionDecision: "deny"` for blocks. The two
`ClientKind` and `OutputFormat` doc-comments are already accurate
internally; only the file-level header is stale.

### F3: Codex session ID fallback can pick up `CLAUDE_SESSION_ID`

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 516–538, 437–462)
**Issue:** When `OutputFormat::Codex` and both the stdin `session_id`
and `CODEX_THREAD_ID` env var are empty, the Codex branch falls through
to `derive_session_id(None)`, which then probes `CLAUDE_SESSION_ID`
before PPID. In a developer environment where both Claude Code and
Codex are configured side-by-side (and `CLAUDE_SESSION_ID` may be
exported from a prior shell session or wrapper), this can silently
cross-contaminate Codex's permit0 session with a Claude session
identifier, fragmenting session-aware pattern detection. The risk is
low (both fallbacks only fire when the explicit sources are absent),
but the failure mode is invisible — the session store accepts whatever
string lands on it.

**Evidence:**

```524:538:crates/permit0-cli/src/cmd/hook.rs
    match format {
        OutputFormat::Codex => {
            if let Some(id) = stdin_session_id.filter(|s| !s.is_empty()) {
                return id;
            }
            if let Ok(id) = std::env::var("CODEX_THREAD_ID") {
                if !id.is_empty() {
                    return id;
                }
            }
            derive_session_id(None)
        }
        OutputFormat::ClaudeCode => derive_session_id(None),
    }
```

```442:462:crates/permit0-cli/src/cmd/hook.rs
    // 2. CLAUDE_SESSION_ID environment variable
    if let Ok(id) = std::env::var("CLAUDE_SESSION_ID") {
        if !id.is_empty() {
            return id;
        }
    }
    // 3. PPID (parent process ID — stable within a Claude Code conversation)
    #[cfg(unix)]
    {
        let ppid = std::os::unix::process::parent_id();
        format!("ppid-{ppid}")
    }
```

**Recommendation:** In the `OutputFormat::Codex` arm, after exhausting
`CODEX_THREAD_ID`, jump straight to the PPID fallback instead of
calling `derive_session_id(None)`. Or, refactor `derive_session_id` to
take an `env_var: &'static str` parameter so the Codex caller can pass
`"CODEX_THREAD_ID"` and skip the Claude-specific env var entirely. The
behavior change is small but eliminates the cross-contamination risk
and makes the precedence chain visually clearer.

### F4: No end-to-end integration test against a stub daemon returning HITL

**Severity:** Minor
**File:** `crates/permit0-cli/tests/cli_tests.rs`
**Issue:** The `a7ebc31f` plan review (Finding #6) specifically called
for an integration test that runs the full binary against a stub HTTP
server and asserts the `--client codex --remote` path produces a deny
envelope when the daemon returns `{"permission": "human", ...}`. The
current coverage of that path is:

- Unit: `codex_remote_human_response_maps_to_deny` (hook.rs:2024–2052)
  exercises `remote_response_to_hook_output` → `hook_output_to_codex`
  composition in-process.
- Integration: `codex_hook_remote_daemon_down_fails_closed`
  (cli_tests.rs:454–494) exercises only the *transport-error* path
  (connection refused on `127.0.0.1:1`).

The full success path (daemon up, returns HITL JSON, hook produces deny
envelope on stdout) has no process-level test. Given that the daemon
HITL wire-format mismatch was a critical finding and lives at the I/O
boundary, an end-to-end stub-server test would have caught it.

**Recommendation:** Add a `codex_hook_remote_hitl_produces_deny_envelope`
test using a `tokio::net::TcpListener` based stub or a `wiremock`
dependency. Plan doc `04-testing.md` Section 8 already sketches the
shape. Low priority since the unit test plus the daemon-side
serialization test (`check_response_serialization`) provides strong
coverage, but it would fully close the loop.

### F5: `--unknown ask` + Codex composition is not directly tested

**Severity:** Minor
**File:** `crates/permit0-cli/src/cmd/hook.rs` (tests), `crates/permit0-cli/tests/cli_tests.rs`
**Issue:** Three of the four `UnknownMode` variants have an explicit
"policy + Codex emit" composition test
(`codex_unknown_defer_yields_empty_stdout`,
`codex_unknown_allow_yields_empty_stdout`,
`codex_unknown_deny_yields_deny_envelope` — hook.rs:1987–2019). The
`Ask` variant is only tested in isolation
(`hook_output_to_codex_ask_maps_to_deny`, hook.rs:1928–1936). Since
the `Ask` path is the *only* `UnknownMode` that flows through
`hook_output_to_codex`'s `Some("ask")` branch (the others rewrite the
output type), this is the most behaviorally distinct combination and
benefits least from the existing isolated coverage.

**Evidence:** Existing pattern at hook.rs:1999-2006:

```1999:2006:crates/permit0-cli/src/cmd/hook.rs
    fn codex_unknown_deny_yields_deny_envelope() {
        let out = HookOutput::ask("permit0: unknown.unclassified");
        let policy_result = apply_unknown_policy(out, true, UnknownMode::Deny);
        let json = hook_output_to_codex(&policy_result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
    }
```

**Recommendation:** Add a 6-line `codex_unknown_ask_yields_deny_envelope`
sibling that builds `HookOutput::ask`, applies `UnknownMode::Ask`
(which is a no-op), pipes through `hook_output_to_codex`, and asserts
the result is a deny envelope with the original reason preserved.

### F6: Stray whitespace cleanup in `serve.rs` is unrelated to the feature

**Severity:** Nit
**File:** `crates/permit0-cli/src/cmd/serve.rs` (lines 166–168)
**Issue:** The PR removes two blank lines (`-\n-\n`) that have nothing
to do with Codex. Cosmetic only — but it adds two lines to the diff
that a reviewer must verify aren't behavioral.

**Evidence:** Git diff shows the only `serve.rs` change is the deletion
of two consecutive blank lines between `check_handler` and
`extract_string_field`.

**Recommendation:** Drop the unrelated whitespace change, or call it
out in the PR description. No source action required if the team's
hygiene policy allows incidental cleanup in feature PRs.

### F7: `build_tool_call_metadata` builds metadata that is silently dropped in remote mode

**Severity:** Nit
**File:** `crates/permit0-cli/src/cmd/hook.rs` (lines 819, 700–705)
**Issue:** `run_inner` always calls `build_tool_call_metadata(&hook_input)`
and stuffs the result into `RawToolCall.metadata`. In local mode this
is correct — the engine writes it into the audit record. In remote
mode, the POST body is built from `tool_name` and `parameters` only
(hook.rs:702-705), so the metadata never reaches the daemon. The
audit record on the daemon side will lack `session_id`, `turn_id`,
`model`, etc. for Codex requests.

**Evidence:**

```819:824:crates/permit0-cli/src/cmd/hook.rs
    let stdin_session_id = hook_input.session_id.clone();
    let metadata = build_tool_call_metadata(&hook_input);
    let tool_call = RawToolCall {
        tool_name: client.strip_prefix(&hook_input.tool_name).to_string(),
        parameters: hook_input.tool_input,
        metadata,
    };
```

```701:710:crates/permit0-cli/src/cmd/hook.rs
    let endpoint = build_check_endpoint(remote);
    let body = serde_json::json!({
        "tool_name": tool_call.tool_name,
        "parameters": tool_call.parameters,
    });

    let response = match ureq::post(&endpoint)
        .set("content-type", "application/json")
        .send_json(body)
```

This matches the documented v2 limitation (`05-limitations.md`
Section 7: "Remote Mode Session Continuity") and the daemon already
accepts a `metadata` field via `CheckRequest` (serve.rs:74-75).

**Recommendation:** Either (a) include `tool_call.metadata` in the
remote POST body now (a one-line change that immediately unlocks
audit context on the daemon, even if cross-call pattern detection
stays a v2 item), or (b) defer entirely and add a `// TODO(v2):`
comment near `evaluate_remote_with_meta` so future readers understand
the missing field is deliberate. Option (a) is preferable — the daemon
already extracts `session_id` from `metadata` (serve.rs:106) and the
audit record gains real value.

## Systemic Assessment

### Architectural Fit

The implementation respects the original "CLI hook adapter only"
contract from `00-overview.md`. No engine, scoring, store, pack,
session, normalizer, or daemon source line is changed (the
`serve.rs` diff is two whitespace deletions, not a behavior change).
The `OutputFormat` indirection is the right abstraction — it's keyed
by `ClientKind` exhaustively (hook.rs:145-153), so adding a new
client variant produces a compile error instead of silently inheriting
the wrong format. The decision to convert `HookOutput` → Codex
envelope at the very end of the pipeline (rather than introducing a
client-aware variant earlier) means `apply_unknown_policy`, remote
response mapping, remote error mapping, and shadow mode all stay
single-implementation. This is the design refinement that the
`600f2a13` plan review specifically pushed for.

A subtle plus: adding `ClientKind::Codex` transitively makes
`POST /api/v1/check` accept `"client_kind": "codex"` because
`serve.rs:35` imports the same enum. The plan acknowledges this as
intended (00-overview.md:127-131) and the daemon's existing
`from_str().unwrap_or(Raw)` fallback path (serve.rs:114-118) means
unknown variants degrade gracefully.

### Security

This change is security-positive on net. The fail-closed `run()`
wrapper (hook.rs:763-786) eliminates an entire class of fail-open
bugs in the Codex path — any error from stdin read, JSON parse,
engine build, permission evaluation, or output serialization is
converted into a deny envelope on stdout (exit 0) instead of being
propagated as a non-zero exit (which Codex treats as fail-open). The
integration test `codex_hook_malformed_stdin_fails_closed`
(cli_tests.rs:425-452) verifies this at the process boundary.

The HITL → deny mapping is the conservative choice in v1 (Codex
`PreToolUse` has no `ask` verdict), and `hook_output_to_codex`'s
defensive `Some(other)` arm (hook.rs:409-411) ensures any future
Claude Code verdict addition fails closed in Codex even if no one
updates the Codex emitter. The corresponding test
`hook_output_to_codex_unknown_decision_label_fails_closed`
(hook.rs:1962-1984) pins this.

The remote-daemon-down case correctly fails closed under Codex (the
Claude path's `ask` fallback becomes `deny` after `hook_output_to_codex`),
which is the right Codex-specific behavior given the no-ask
constraint. This is verified by `codex_remote_transport_error_maps_to_deny`
(hook.rs:2054-2074) and the integration test
`codex_hook_remote_daemon_down_fails_closed` (cli_tests.rs:454-494).

The "never emit `permissionDecision: allow`" invariant has both a
structural unit test (`hook_output_to_codex_never_emits_allow_decision`,
hook.rs:1939-1960) and a process-level integration test across four
combinations (`codex_hook_never_emits_permission_decision_allow`,
cli_tests.rs:549-597). Structural JSON checking (not substring
matching) means a deny reason that happens to contain the literal word
"allow" won't trigger a false positive.

The one remaining attack-surface question is F3 (CLAUDE_SESSION_ID
cross-contamination), which is a *correctness* concern more than a
security one — but in a multi-tenant agent workstation, the session
boundary is also a privacy/scope boundary, so cross-contaminated
session IDs could leak action history between agent runtimes.

### Backward Compatibility

`HookInput` gained seven optional Codex-specific fields, all with
`#[serde(default)]`. The Claude Code minimal payload still
deserializes identically — verified by `hook_input_claude_code_compat`
(hook.rs:1731-1747) and the integration test
`codex_hook_minimal_claude_payload_does_not_error` (cli_tests.rs:524-546).
The four pre-existing client variants
(`ClaudeCode`/`ClaudeDesktop`/`OpenClaw`/`Raw`) keep their existing
`OutputFormat::ClaudeCode` mapping and their existing prefix-strip
behavior. The pre-existing `client_kind_parses_from_string` test
(hook.rs:1364-1392) still passes unmodified, and no existing serialization
test was relaxed.

The `--client codex` flag is purely additive; no flag default changes
and no existing CLI invocation switches behavior. The
`PERMIT0_CLIENT=codex` env var path works because the env-var
override already routes through `ClientKind::from_str` (main.rs:243-248).

The `CheckResponse` HITL wire shape is *not* changed — the daemon
still serializes `Permission::HumanInTheLoop` as `"human"`
(serve.rs:576), and that value is now correctly recognized by both
the Claude Code and Codex remote paths via the
`"human" | "humanintheloop"` match arm. This is also a Claude Code
bug fix (previously HITL on Claude Code remote mode produced a
confusing "unknown permission value 'human'" reason), regression-locked
by `remote_response_parses_actual_daemon_human_shape` (hook.rs:1599-1619)
and `remote_response_human_maps_to_ask` (hook.rs:1523-1552).

### Testing Coverage

Test coverage is the strongest aspect of this PR. Counts in
`crates/permit0-cli`:

| Surface | New Codex-specific tests | Process-level |
|---------|--------------------------|---------------|
| Client kind parsing & strip | 3 | 0 |
| `OutputFormat` mapping | 1 | 0 |
| `HookInput` deserialization | 3 | 1 (`codex_hook_minimal_claude_payload_does_not_error`) |
| `build_tool_call_metadata` | 3 | 0 |
| Codex output (`codex_output`, `hook_output_to_codex`) | 9 | 0 |
| `apply_unknown_policy` + Codex composition | 3 | 0 |
| Remote daemon mapping | 2 | 0 |
| Session ID derivation | 4 | 0 |
| End-to-end binary invocation | 0 | 6 |

The six integration tests cover the four most dangerous Codex failure
modes (unknown defer, unknown deny, malformed stdin, remote-down, shadow
mode, never-emit-allow). The unit tests pin every internal helper
contract, and the `hook_output_to_codex_never_emits_allow_decision`
test uses structural JSON comparison (not substring matching) to
guarantee the "no allow envelope" invariant.

Gaps (all flagged as Minor in F4 and F5):

- No process-level test against a stub HTTP server returning a
  successful HITL response (the daemon-up case).
- No `--unknown ask` + Codex composition test (only the helper-level
  `hook_output_to_codex_ask_maps_to_deny` exists).

Neither gap is a correctness risk given the unit-test density, but
both are easy to close.

## What Was Done Well

- **Fail-closed wrapper is exactly the right shape.** The `run` /
  `run_inner` split (hook.rs:752-786) makes the Codex error-handling
  contract a single, tested seam. The Claude Code path is bit-identical
  to before; the Codex path is a controlled fallback that converts
  errors to deny envelopes. This addresses critical finding #1 from
  the `600f2a13` plan review with a structural fix rather than scattering
  `?` rewrites across the function.
- **End-of-pipeline conversion via `hook_output_to_codex`.** Reusing
  the `HookOutput` shape for unknown policy, remote response, remote
  error, and shadow mode — and converting only at emit — avoided a
  Cartesian explosion of (mode × client) code paths. The same change
  cleanly addresses both `apply_unknown_policy`-not-Codex-aware and
  shadow-mode-emits-allow concerns from `a7ebc31f`.
- **HITL wire-format fix bundled in.** Adding `"human"` as a
  recognized wire value (hook.rs:586) fixes the latent Claude Code
  remote HITL bug at the same time as enabling Codex remote mode.
  The regression test `remote_response_parses_actual_daemon_human_shape`
  pins the actual `serve.rs` JSON shape, so a future server-side
  rename surfaces as a test failure here.
- **Structural JSON assertions, not substring matching.** The Codex
  output tests parse the envelope and compare specific fields
  (`parsed["hookSpecificOutput"]["permissionDecision"]`). This avoids
  the brittleness the `a7ebc31f` review flagged in finding #7.
- **Exhaustive `OutputFormat::from_client` match** (hook.rs:146-152)
  forces a deliberate decision for every new `ClientKind` variant.
- **Defensive `Some(other)` arm in `hook_output_to_codex`**
  (hook.rs:409-411). If a future `permissionDecision` value is added
  to Claude Code's vocabulary, Codex will fail closed rather than
  pass the unrecognized envelope through.
- **Empty-string handling everywhere it matters.** `build_tool_call_metadata`
  drops empties (hook.rs:494), `derive_session_id_for_format` filters
  empties at every step (hook.rs:521, 526, 530), `extract_string_field`
  in serve.rs (lines 169-178) also filters empties. Verified by
  `build_tool_call_metadata_drops_empty_strings` and
  `codex_session_id_empty_stdin_falls_through`.
- **Codex protocol pinning.** Tests assert the exact wire shape Codex
  expects: `hookSpecificOutput.hookEventName == "PreToolUse"`,
  `permissionDecision == "deny"`, empty stdout for allow/defer.
  Process-level tests use `output.stdout.is_empty()` (true byte-level
  zero) instead of `String::from_utf8_lossy(&output.stdout).trim().is_empty()`
  — important because Codex's invalid-JSON warning would fire on a
  bare newline.

## Verified Correctness

- [x] `ClientKind::Codex` strips `mcp__<server>__<tool>` to bare tool
  name, including the Codex-sanitized form `mcp__permit0_gmail__gmail_send`
  — confirmed in `codex_strips_mcp_double_underscore_prefix`
  (`crates/permit0-cli/src/cmd/hook.rs:1646-1668`).
- [x] `HookOutput::ask` produced from the canonical daemon
  `"human"` value flows through `hook_output_to_codex` to a deny envelope
  with the action-type-bearing reason — confirmed in
  `codex_remote_human_response_maps_to_deny`
  (`crates/permit0-cli/src/cmd/hook.rs:2023-2052`).
- [x] Stdin parse errors in Codex mode produce a deny envelope on
  stdout, never a bare non-zero exit — confirmed by
  `codex_hook_malformed_stdin_fails_closed`
  (`crates/permit0-cli/tests/cli_tests.rs:425-452`).
- [x] Shadow mode + Codex produces exactly zero stdout bytes (no
  allow envelope, no trailing newline) — confirmed by
  `codex_hook_shadow_produces_empty_stdout`
  (`crates/permit0-cli/tests/cli_tests.rs:497-522`).
- [x] The hook never emits `permissionDecision: "allow"` across
  defer/allow/deny/shadow combinations — confirmed by
  `codex_hook_never_emits_permission_decision_allow`
  (`crates/permit0-cli/tests/cli_tests.rs:549-597`) using structural
  JSON comparison.
- [x] `apply_unknown_policy` is invoked on the remote-mode output
  before the Codex emit step — confirmed at
  `crates/permit0-cli/src/cmd/hook.rs:844`.
- [x] Daemon transport errors fail closed under Codex (Claude's `ask`
  fallback becomes Codex's `deny`) — confirmed by
  `codex_remote_transport_error_maps_to_deny`
  (`crates/permit0-cli/src/cmd/hook.rs:2054-2074`) and integration test
  `codex_hook_remote_daemon_down_fails_closed`
  (`crates/permit0-cli/tests/cli_tests.rs:454-494`).
- [x] HTTP status errors from the daemon produce a deny under Codex
  carrying the daemon's own body so operators can debug — confirmed
  by `remote_http_status_error_maps_to_deny_with_daemon_body`
  (`crates/permit0-cli/src/cmd/hook.rs:1194-1222`) composed with
  `hook_output_to_codex_deny_uses_existing_reason`
  (`crates/permit0-cli/src/cmd/hook.rs:1917-1925`).
- [x] `HookInput` deserializes both Claude minimal payload and full
  Codex payload (including `transcript_path: null`) — confirmed by
  `hook_input_claude_code_compat`, `codex_hook_input_full_payload`,
  and `hook_input_codex_null_transcript_path`
  (`crates/permit0-cli/src/cmd/hook.rs:1697-1846`).
- [x] `build_tool_call_metadata` drops empty-string fields so audit
  queries that filter by presence are not polluted — confirmed by
  `build_tool_call_metadata_drops_empty_strings`
  (`crates/permit0-cli/src/cmd/hook.rs:1810-1831`).
- [x] `ClientKind` parser is case-sensitive for the new `codex`
  alias, matching the existing parser contract — confirmed by
  `codex_client_kind_parser_is_case_sensitive`
  (`crates/permit0-cli/src/cmd/hook.rs:1636-1643`).
- [x] Adding `Codex` to `ClientKind` transitively allows the daemon
  to accept `{"client_kind": "codex"}` via `ClientKind::from_str`
  on serve.rs — confirmed by the import at
  `crates/permit0-cli/src/cmd/serve.rs:35` and the runtime resolution
  at `crates/permit0-cli/src/cmd/serve.rs:114-122`.
- [x] Daemon HITL wire shape (`Permission::HumanInTheLoop.to_string()
  → "HUMAN" → to_lowercase() = "human"`) is pinned by
  `remote_response_parses_actual_daemon_human_shape`
  (`crates/permit0-cli/src/cmd/hook.rs:1598-1619`), verified against
  the actual `Permission::Display` impl at
  `crates/permit0-types/src/permission.rs:13-21` and the daemon's
  `record_and_respond` at `crates/permit0-cli/src/cmd/serve.rs:576`.
- [x] All `Result`-returning steps in `run_inner` (stdin read, JSON
  parse, engine build, session store open, permission evaluation,
  output serialize) route through the Codex error wrapper in `run`
  — confirmed by reading `crates/permit0-cli/src/cmd/hook.rs:763-786`
  and matching `?` usages in `run_inner` (lines 807-994).
- [x] `clippy --all-targets -- -D warnings` passes on `permit0-cli`.
- [x] All 80 `permit0-cli` unit tests and 21 integration tests pass
  (`cargo test -p permit0-cli`).
- [x] `cargo fmt --check` passes on `permit0-cli` (the workspace-wide
  format diff comes from an unrelated `crates/permit0-dsl/src/normalizer.rs`
  pre-existing drift, not from any file in this PR).
