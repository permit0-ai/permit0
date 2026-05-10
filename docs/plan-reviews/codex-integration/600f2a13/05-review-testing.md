# Review: 04 - Test Plan

**Reviewer:** Cursor Agent (600f2a13)
**Plan doc:** `docs/plans/codex-integration/04-testing.md`
**Review date:** 2026-05-10

## Verdict

REQUEST CHANGES

## Summary

The proposed tests cover useful pure helpers for parsing, prefix stripping, session derivation, and deny-envelope serialization. They miss the most important Codex risk: full-process fail-open behavior and exact stdout contracts for allow/defer/shadow paths.

## Detailed Findings

### Finding 1: Missing process-level fail-open tests

**Severity:** Critical
**Location:** Unit Tests, Integration Tests, Edge Cases
**Claim:** The test plan covers serialization and logic for Codex behavior.
**Reality:** Codex's critical failures happen when the process exits non-zero or emits unsupported output. The current hook can do that through `?` on JSON parsing, engine construction, permission evaluation, and serialization in `crates/permit0-cli/src/cmd/hook.rs:491-498`, `crates/permit0-cli/src/cmd/hook.rs:544-583`, and `crates/permit0-cli/src/cmd/hook.rs:671-672`. The proposed tests do not run the binary through malformed stdin, bad packs, daemon-down remote mode, or evaluation errors.
**Recommendation:** Add integration tests that execute `permit0 hook --client codex` and assert fail-closed behavior for malformed stdin, missing/invalid pack config, remote daemon unavailable, remote non-2xx, and malformed remote JSON.

### Finding 2: Allow/defer integration tests are too loose

**Severity:** Major
**Location:** Codex Hook End-to-End: Allow, Unknown Tool Defer
**Claim:** The allow test can accept empty stdout or stdout containing no `permissionDecision: "allow"`.
**Reality:** Codex allow/defer must be exact: exit 0 with zero stdout bytes. A deny envelope, unsupported ask output, or malformed JSON could satisfy "no allow" while still violating the contract. Existing Claude tests assert exact envelope fields in `crates/permit0-cli/src/cmd/hook.rs:693-748`; Codex needs equally exact process assertions.
**Recommendation:** Assert `output.status.success()` and `output.stdout.is_empty()` for allow/defer/shadow allow paths. Assert exact JSON envelope fields for deny/HITL paths.

### Finding 3: Remote metadata and HITL tests are missing

**Severity:** Major
**Location:** Integration Tests, Edge Cases
**Claim:** Remote mode works unchanged, and session derivation is covered by helper tests.
**Reality:** The current remote helper omits metadata in `crates/permit0-cli/src/cmd/hook.rs:435-443`, while the daemon request can accept `metadata` and `client_kind` in `crates/permit0-cli/src/cmd/serve.rs:53-78`. The current hook also expects `"humanintheloop"` while the daemon emits `"human"` for HITL.
**Recommendation:** Add tests for the remote request body and remote response mapping. Pin `serve.rs`'s actual HITL wire value and assert Codex maps it to deny, not unknown permission.

### Finding 4: Daemon-down expectation is wrong for current Claude remote behavior

**Severity:** Major
**Location:** Edge Cases to Verify
**Claim:** `--client codex --remote` with daemon down should deny with "remote unavailable" and is the same as the Claude path.
**Reality:** Current Claude remote transport errors map to `HookOutput::ask("permit0 remote unavailable: ...")` in `crates/permit0-cli/src/cmd/hook.rs:417-428`, and tests assert that ask behavior in `crates/permit0-cli/src/cmd/hook.rs:844-871`.
**Recommendation:** Specify Codex behavior separately. Codex should fail closed as deny or exit code 2, but that is not the same as the current Claude path.

### Finding 5: Manual script is not a substitute for a checked fixture

**Severity:** Minor
**Location:** Manual Test Script
**Claim:** Create `scripts/test-codex-hook.sh` for interactive testing.
**Reality:** The script is draft-only and not present in the current repo. More importantly, manual scripts do not protect the Codex empty-stdout invariant in CI.
**Recommendation:** Keep the manual script as an optional smoke test, but move the important cases into `crates/permit0-cli/tests/cli_tests.rs` or unit-testable helpers.

## Verified Claims

- Existing `hook.rs` tests cover Claude output serialization, unknown mode, client parsing, prefix stripping, remote response mapping, and remote error mapping in `crates/permit0-cli/src/cmd/hook.rs:681-1245`.
- `ClientKind` parsing and prefix stripping are pure functions, so the proposed Codex unit tests fit the current test style.
- `HookInput` serde compatibility can be tested in the existing `hook.rs` test module.
- `codex_output_never_contains_allow` is the right invariant to test, but it needs a full `run()` integration counterpart.
- `cli_tests.rs` already has process-level hook coverage for a safe email call in `crates/permit0-cli/tests/cli_tests.rs:129-163`.
- `gmail_read` has a minimal read risk rule in `packs/permit0/email/risk_rules/read.yaml:1-10`, so it is a plausible low-risk allow fixture.
- Existing pack snapshot tests verify email normalizer behavior independent of CLI scoring in `crates/permit0-cli/tests/pack_snapshot.rs:160-259`.

## Questions for the Author

1. Should CI run all `permit0-cli` tests, or is the `codex` name filter intended only as a fast subset?
2. Should the manual script capture stdout byte counts so empty output is visible?
