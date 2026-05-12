# Review: 04 — Test Plan

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/04-testing.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The 12 unit tests cover the core happy-path behaviors well (parsing,
Codex stripping, output serialization, session-ID derivation). Several
tests have substring-match brittleness, the regression list omits some
of the most relevant existing tests, integration coverage of remote
mode + Codex is missing entirely, and there is no test for the
critical "Codex must NOT see permissionDecision: allow even on shadow"
invariant. The lack of a remote-mode Codex test means the issues
flagged in `02-review-implementation.md` Finding 1 would not be caught.

## Detailed Findings

### Finding 1: Test 8 (`codex_output_never_contains_allow`) is too narrow

**Severity:** Major
**Location:** Test 8, body
**Claim:** Tests that `codex_output` never produces
`"permissionDecision":"allow"` in any form.
**Reality:** The test does substring matching for two specific
spacings: `r#""permissionDecision":"allow""#` and
`r#""permissionDecision": "allow""#`. But (a) `serde_json::to_string`
only emits the no-space form, so the second check is dead, and (b) a
deny reason that happens to contain the literal text
"permissionDecision: allow" (e.g. a meta-message: "Codex rejects
permissionDecision: allow") would falsely fail. Worse, the test only
covers `codex_output` output — not the full pipeline. The shadow path,
the unknown-mode-rewrite path, and the remote path all bypass
`codex_output` and could re-introduce the bug.
**Recommendation:** Replace substring checks with structural checks:
```rust
let parsed: Value = serde_json::from_str(&json).unwrap();
assert_ne!(parsed["hookSpecificOutput"]["permissionDecision"], "allow");
```
And add an integration test that runs the FULL hook pipeline through
the binary with `--client codex` and asserts no `"permissionDecision":
"allow"` appears in stdout for any combination of (allow/deny/HITL) ×
(local/remote) × (shadow/no-shadow) × (each --unknown mode).

### Finding 2: No test for remote-mode + Codex pathway

**Severity:** Major
**Location:** Whole "Integration Tests" section
**Claim:** Tests 1–3 cover Codex hook end-to-end.
**Reality:** All three integration tests are local-mode (no
`--remote` flag). The remote-mode path (`hook.rs:511-542`) is
exactly where `02-review-implementation.md` Finding 1 lives —
`codex_output(result.permission, ...)` doesn't compile in remote
mode. There must be at least one integration test that exercises
`--client codex --remote http://...` against a stub HTTP server.
**Recommendation:** Add an integration test using something like
`mockito` or a hand-rolled `tokio::spawn` echo server that:
1. Starts a stub /api/v1/check returning each of `{"permission":
   "allow"}`, `{"permission": "deny", "block_reason": "..."}`,
   and `{"permission": "human"}` (note the canonical spelling — see
   Finding 5 below).
2. Runs `permit0 hook --client codex --remote ...` against it.
3. Asserts the stdout matches the Codex envelope (or is empty for
   allow).

### Finding 3: Regression list omits the actually-load-bearing tests

**Severity:** Major
**Location:** "Regression Tests" subsection
**Claim:** Lists `parse_hook_input`, `hook_output_*_serialization`,
`apply_unknown_policy_*`, `remote_response_*`, `remote_error_*`.
**Reality:** This is OK but misses some tests that lock down current
behavior the Codex changes will mechanically affect:
- `derive_session_id_explicit` and `derive_session_id_ppid_fallback`
  (`hook.rs:1075-1090`) — must keep working since the new
  `derive_session_id_for_format` should call `derive_session_id`
  for ClaudeCode mode.
- `client_kind_parses_from_string` (`hook.rs:1043-1072`) — the new
  `Codex` variant adds parses without breaking existing ones.
- `remote_response_parses_real_check_response_shape`
  (`hook.rs:1226-1245`) — this test is misnamed (it doesn't actually
  test the real shape; see Finding 5) but the plan should still call
  it out as a regression to keep.
**Recommendation:** Expand the regression list to enumerate all
`hook.rs` tests that touch `ClientKind`, `derive_session_id`, or
`RemoteCheckResponse`. A grep-based "all tests in
`crates/permit0-cli/src/cmd/hook.rs`" is fine as a default.

### Finding 4: Test 12 (`codex_unknown_defer_produces_no_output`) duplicates Test 5

**Severity:** Minor
**Location:** Test 12 body
**Claim:** Tests defer mode produces no output.
**Reality:** The test body is literally identical to Test 5
(`codex_output_allow_is_none`). It tests the same `codex_output`
function with the same input. To be meaningful, Test 12 should
exercise the `apply_unknown_policy(...)` → Codex output
combination, asserting that `UnknownMode::Defer` + Codex output
yields zero stdout bytes.
**Recommendation:** Replace the body with:
```rust
let out = HookOutput::ask("permit0: unknown.unclassified");
let policy_result = apply_unknown_policy(out, true, UnknownMode::Defer);
let codex_serialized = /* the Codex output formatter */;
assert_eq!(codex_serialized.len(), 0);
```
This requires the Codex output formatter to take a `HookOutput` (or
the refactor proposed in `03-review-implementation.md` Finding 3).

### Finding 5: No test for the daemon's actual permission spelling

**Severity:** Major
**Location:** Both unit and integration test sections
**Claim:** None directly.
**Reality:** As analyzed in `02-review-protocol.md` Finding 1, the
daemon emits `permission: "human"` (verified via
`Permission::Display::HumanInTheLoop` writes "HUMAN", then `serve.rs:578`
lowercases). The hook's existing matcher expects `"humanintheloop"`,
so HITL in remote mode silently misroutes today. The Codex test plan
must add a test asserting Codex remote mode handles `"human"`
correctly. Without it, the new test suite would pass while the new
remote-mode HITL path is broken.
**Recommendation:** Add unit test `codex_remote_human_maps_to_deny`
that builds a `RemoteCheckResponse` with `permission: "human"` and
asserts the Codex envelope is `permissionDecision: "deny"` with the
proper risk reason — NOT "unknown permission value 'human'".

### Finding 6: Manual test script omits `--remote` and shadow combinations

**Severity:** Minor
**Location:** "Manual Test Script" subsection
**Claim:** Three test cases exercise Codex hook with various
verdicts.
**Reality:** All three cases are local-mode. Test 3 uses `--shadow`
but not `--remote`. The script should at minimum include a fourth
case for `--remote --shadow` since that combination has the most
moving parts and is most likely to hide the bugs flagged in
`02-review-implementation.md`.
**Recommendation:** Add a test 4 against a running daemon (or skip
gracefully if the daemon isn't reachable):
```bash
echo "=== Test 4: Remote + shadow (expect exit 0, stderr log only) ==="
if curl -sf http://127.0.0.1:9090/api/v1/health >/dev/null; then
  echo '{...}' | $PERMIT0 hook --client codex --remote http://127.0.0.1:9090 --shadow
  echo "Exit code: $?"
else
  echo "(daemon not running, skipping)"
fi
```

### Finding 7: Edge-case matrix missing two important rows

**Severity:** Minor
**Location:** "Edge Cases to Verify" table
**Claim:** Eight scenarios listed.
**Reality:** Two important gaps:
- "Codex sends only `tool_name` and `tool_input` (Claude-style minimal
  payload)": the implementation plan claims backward compat. Test
  exists at unit level (Test 4) but not in the integration matrix.
- "Codex sends `permissionDecision: 'allow'` rejected behavior verified":
  there's no scenario testing what happens when permit0 accidentally
  emits the forbidden form. A test could pipe a known-bad output and
  verify the assertion fires.
**Recommendation:** Add two rows: (a) "Minimal Claude-style payload
into `--client codex` hook" → "Same behavior as full payload, no
errors", (b) "Hook accidentally emits `permissionDecision: allow`" →
"Test asserts this never happens via the structural check."

### Finding 8: CI integration filter `-- codex` is fragile

**Severity:** Nit
**Location:** "CI Integration" subsection
**Claim:** `cargo nextest run -p permit0-cli -- codex` runs all
tests with "codex" in the name.
**Reality:** `--` separates cargo args from test runner args. For
nextest, the test filter is positional, so `cargo nextest run -p
permit0-cli codex` (no `--`) is the conventional form. The `--`
form may work but is unidiomatic. More importantly, this filter
won't catch bugs in non-codex tests that the Codex plan touches
(e.g. the existing `client_kind_parses_from_string` test, which
adds a Codex assertion). The CI step should run the full
`permit0-cli` test suite for any change to Codex code.
**Recommendation:** Drop the filter — just run `cargo nextest run
-p permit0-cli`. The Codex tests are fast enough; running them
all keeps the CI signal strong.

## Verified Claims

- `HookInput` deserialization correctly accepts both Claude minimal
  and Codex extended payloads given the proposed
  `#[serde(default)] Option<...>` fields. Tested via the existing
  `parse_hook_input` test at `hook.rs:682-687` and validated
  conceptually for the new fields.
- `serde_json::to_string` produces no whitespace between `:` and the
  value, so the substring `r#""permissionDecision":"allow""#` would
  match the actual output (verified by inspection of serde_json
  default settings — no `pretty` flag).
- `Permission::Allow`, `Permission::Deny`, and
  `Permission::HumanInTheLoop` are the three variants
  (`crates/permit0-types/src/permission.rs:7-11`); the test
  enumeration in Test 8 covers all of them.
- `apply_unknown_policy` is unit-tested at `hook.rs:769-842` with
  six existing cases. The Codex plan's regression list correctly
  references this family.
- The integration test pattern (pipe stdin, capture stdout, assert
  shape) follows the existing `hook_with_safe_email` test at
  `crates/permit0-cli/tests/cli_tests.rs:130-163`. A Codex variant
  fits the existing scaffold cleanly.

## Questions for the Author

1. Will the integration tests need a stub HTTP server for remote-mode
   Codex testing? If so, which crate is acceptable
   (`mockito`, `wiremock`, hand-rolled hyper)?
2. Should `pack_snapshot.rs` (an existing snapshot test) be extended
   to cover the Codex prefix-stripping path? Today it tests
   `RawToolCall` → `NormAction` directly without a hook layer; not
   strictly needed, but worth deciding.
3. Is there a budget for adding property tests? The serialization
   round-trip is a natural property-test target (any
   `(Permission, String)` pair → Codex output → reparseable JSON).
4. The plan adds `cargo nextest run -p permit0-cli -- codex` to CI;
   is the existing CI already running the full suite? If so, the new
   step is redundant. If not, the existing CI is under-tested.
