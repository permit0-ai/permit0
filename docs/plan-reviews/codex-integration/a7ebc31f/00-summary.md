# Plan Review Summary: codex-integration

**Reviewer:** Cursor Agent (a7ebc31f)
**Review date:** 2026-05-10
**Plan location:** `docs/plans/codex-integration/`

## Overall Verdict

REQUEST CHANGES

## Key Findings

Ordered by severity:

1. **Critical — HITL wire-format mismatch the Codex remote path
   inherits.** The daemon emits `permission: "human"` for
   `Permission::HumanInTheLoop`
   (`crates/permit0-cli/src/cmd/serve.rs:578` calls
   `to_string().to_lowercase()`, and `Permission::Display::HumanInTheLoop`
   writes `"HUMAN"` at `crates/permit0-types/src/permission.rs:17`).
   The hook's `remote_response_to_hook_output` matcher at
   `crates/permit0-cli/src/cmd/hook.rs:317-336` only knows
   `"humanintheloop"`, so the daemon's `"human"` falls into the
   `other` branch and produces "permit0 remote: unknown permission
   value 'human'" as the deny reason. The OpenClaw TS client correctly
   aligns with the daemon at
   `integrations/permit0-openclaw/src/types.ts:11`
   (`Permission = "allow" | "deny" | "human"`). The Codex plan
   inherits this latent bug verbatim and does not mention it.
   (See `02-review-protocol.md` Finding 1 and
   `06-review-limitations.md` Finding 1.)

2. **Critical — Remote-mode `codex_output(result.permission, ...)`
   does not compile as written.** `02-implementation.md` Change 6
   shows the Codex output branch using `result.permission`, but in
   the remote-mode block (`hook.rs:511-542`) `result` is
   `(HookOutput, bool)` from `evaluate_remote_with_meta`, not a
   `PermissionResult`. The plan's "Remote mode" subsection waves
   this away as "translated through `codex_output` instead of
   `remote_response_to_hook_output`" without showing the actual
   wiring. (See `03-review-implementation.md` Finding 1.)

3. **Major — v1 scope contradicts limitations doc on session-aware
   remote mode.** `00-overview.md` lists "Maintain session context
   for cross-call pattern detection" as a v1 goal, and
   `03-configuration.md` "Session-Aware Mode" claims the hook passes
   `session_id` to the daemon. But the implementation plan does NOT
   modify the remote POST body, and `05-limitations.md` Section 7
   correctly defers it to v2. Three docs disagree. (See
   `01-review-overview.md` Finding 1, `04-review-configuration.md`
   Finding 1, `06-review-limitations.md` Finding 2.)

4. **Major — Shadow mode + Codex is sketched in prose, not in code.**
   The existing shadow path emits `HookOutput::allow()` and
   unconditionally `println!`s the JSON envelope, which for Codex
   would be `permissionDecision: "allow"` — exactly the form Codex
   rejects. The plan says "exit 0 with empty stdout" but doesn't
   show the conditional skip. (See `03-review-implementation.md`
   Finding 2.)

5. **Major — `apply_unknown_policy` is not Codex-aware.** The
   function rewrites `HookOutput`s assuming Claude envelopes. For
   Codex, `Defer` must produce zero stdout (no envelope at all),
   `Allow` must NOT produce `permissionDecision: "allow"`, and
   `Ask` must produce a deny envelope. None of these branches are
   sketched. (See `03-review-implementation.md` Finding 3.)

6. **Major — No integration test covers `--client codex --remote`.**
   All three proposed integration tests are local-mode. The remote-
   mode path is exactly where findings #1 and #2 live; without an
   integration test against a stub HTTP server, those bugs would
   ship green. (See `05-review-testing.md` Finding 2.)

7. **Major — Test 8 (`codex_output_never_contains_allow`) only
   covers `codex_output` in isolation.** Shadow mode and unknown-
   mode-rewrite paths can re-introduce the forbidden output without
   tripping the test, and the test's substring matching is brittle.
   (See `05-review-testing.md` Finding 1 and
   `06-review-limitations.md` Finding 4.)

8. **Major — "No daemon changes" claim is misleading.** Adding
   `Codex` to `ClientKind` (in hook.rs) transitively makes the daemon
   accept `{"client_kind": "codex"}` because `serve.rs:35` imports
   the same enum. This is intended but should be acknowledged as a
   side-effect rather than denied. (See `01-review-overview.md`
   Finding 2 and `03-review-implementation.md` Finding 6.)

9. **Major — `derive_session_id_*` snippets in protocol and
   implementation docs disagree.** Protocol shows
   `derive_session_id_codex(stdin, explicit) -> String`;
   implementation shows `derive_session_id_for_format(format, stdin,
   explicit) -> String`. Pick one. (See `02-review-protocol.md`
   Finding 2.)

10. **Major — Unverified Codex version claim.** Both
    `00-overview.md` and `03-configuration.md` mention Codex 0.110+
    without citation. If the version is wrong, users will install a
    Codex without hook support, hook config will be silently
    ignored, and they'll think permit0 is broken. (See
    `02-review-protocol.md` Question 1 and
    `04-review-configuration.md` Finding 3.)

11. **Major — Network sandbox guidance is contradictory.**
    `03-configuration.md` "Network Access Requirement" gives two
    options as alternatives when only one will be true for a given
    Codex version. (See `04-review-configuration.md` Finding 2.)

Plus several minor and nit-level findings on data-flow diagram
omissions, test name duplication, calibration timeout behavior,
project-local hook ergonomics, and PermissionRequest race-condition
risk in v2 design.

## Statistics

| Metric | Count |
|--------|-------|
| Plan docs reviewed | 6 |
| Critical findings | 2 |
| Major findings | 17 |
| Minor findings | 11 |
| Nits | 8 |
| Verified claims | 36 |
| Open questions | 18 |

(Counts span all six per-doc reviews.)

## Recommendation

The team should **not** proceed with implementation as-is. Two
critical issues will produce a Codex remote mode that visibly
misroutes HITL verdicts and code that does not compile in the remote
arm. Both can be fixed without major refactors:

1. Fix the wire-format bug (or accept both `"human"` and
   `"humanintheloop"` in the matcher) and update the masking tests at
   `hook.rs:1183, 1231`. This is small enough to bundle into the
   Codex PR and leaves Claude Code remote mode also correct.
2. Sketch the actual remote-mode Codex output flow — either a new
   `codex_output_from_remote(&RemoteCheckResponse) -> Option<String>`
   or a refactor of `evaluate_remote_with_meta` to surface `Permission`
   directly. Update `02-implementation.md` Change 6 with the real
   `run()` body.
3. Reconcile the v1 scope: pick whether session-aware remote mode is
   v1 or v2, and align `00-overview.md`, `03-configuration.md`, and
   `05-limitations.md`.
4. Add at least one integration test that runs `permit0 hook --client
   codex --remote http://...` against a stub server with each of the
   three permission shapes (including `"human"`).
5. Update `apply_unknown_policy` and shadow mode to be format-aware,
   with explicit code in `02-implementation.md`.

The configuration doc, limitations doc, and the bulk of the protocol
doc are otherwise solid. The plan's overall architecture (CLI-only
change, reuse engine and packs, single new ClientKind variant) is
sound — only the I/O layer specifics need tightening.

After the above changes, this plan is a strong APPROVE candidate.
