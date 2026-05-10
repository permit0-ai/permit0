# Plan Review Summary: codex-integration

**Reviewer:** Cursor Agent (a7ebc31f)
**Review date:** 2026-05-10 (initial), updated for docs 06 and 07
**Plan location:** `docs/plans/codex-integration/`

## Overall Verdict

APPROVE WITH COMMENTS

(Revised from REQUEST CHANGES after the implementation landed and two
new docs — `06-real-codex-testing.md` and `07-packaging.md` — addressed
the previous critical findings.)

## What changed since the initial review

The original review (this same subdirectory, files
`01-review-overview.md` through `06-review-limitations.md`) issued
REQUEST CHANGES on two critical findings against
`02-implementation.md`:

1. The HITL wire-format mismatch (daemon emits `"human"`, hook matcher
   expected `"humanintheloop"`).
2. The remote-mode `codex_output(result.permission, ...)` snippet did
   not compile because remote mode returns `(HookOutput, bool)`, not a
   `PermissionResult`.

Both are now resolved in the merged code. Verified at
`crates/permit0-cli/src/cmd/hook.rs`:

- `hook_output_to_codex(output: &HookOutput) -> Option<String>` at
  lines 441-471 accepts a `HookOutput` (not a `Permission`), so it
  works for both local and remote arms uniformly.
- `emit_hook_output` at lines 480-491 routes by `OutputFormat` and
  correctly skips the println for `OutputFormat::Codex` when there's no
  envelope to write (no trailing newline).
- The outer `run` at lines 831-864 wraps the whole pipeline so any
  error in Codex mode becomes a structured deny envelope rather than a
  silent fail-open.
- The HITL → deny mapping appends a `CODEX_HITL_MARKER` to the reason,
  matching the per-tier behavior table in
  `integrations/permit0-codex/README.md:113-118`.

The two new plan docs cover (a) the live-Codex test transcript that
verified the implementation against Codex 0.130.0-alpha.5, and (b) the
packaging layout under `integrations/permit0-codex/`. New findings
below are about those two docs, not about the original implementation.

## Key Findings (new + still-open from prior review)

Ordered by severity. Items marked **(prior)** are from the original
review and have not been addressed by the new docs; items marked
**(new)** come from the 06/07 reviews.

### Major

1. **(new) `dev-test-rig/codex-demo` symlinks `~/.codex/auth.json` into
   `/tmp/permit0-codex-test/`.** `/tmp/` is mode 1777 on macOS; any
   local user can dereference the symlink to read the credentials.
   `~/.codex/` is mode 700 by default. See
   `08-review-packaging.md` Finding 4.

2. **(new) Cleanup recipe wipes the entire
   `requirements_toml_base64` key.** Both `06-real-codex-testing.md`
   and `integrations/permit0-codex/README.md` instruct
   `defaults delete com.openai.codex requirements_toml_base64`, which
   removes any non-permit0 managed config that share the key. See
   `07-review-real-codex-testing.md` Finding 1.

3. **(new) `integrations/README.md` table format mismatch.**
   `07-packaging.md` Change 4 proposes adding Codex to the primary
   framework table; the actual file already has a separate "CLI-hook
   integrations" table where Codex is listed. The plan would either
   silently double-list or destroy the existing layout. See
   `08-review-packaging.md` Finding 1.

4. **(prior) v1 scope contradicts limitations doc on session-aware
   remote mode.** `00-overview.md` lists "Maintain session context for
   cross-call pattern detection" as a v1 goal; `05-limitations.md` §7
   explicitly defers it to v2. The new docs do not reconcile this.
   See `01-review-overview.md` Finding 1, `04-review-configuration.md`
   Finding 1, `06-review-limitations.md` Finding 2.

5. **(prior) Network sandbox guidance is contradictory.**
   `03-configuration.md` "Network Access Requirement" gives two
   options as alternatives when only one is actually required.
   Untouched by 06/07. See `04-review-configuration.md` Finding 2.

### Minor

6. **(new) `--uninstall` flag claimed but not implemented.**
   `07-packaging.md` Change 2 says `install-managed-prefs.sh` "includes
   a `--uninstall` flag"; the committed script has no argument
   parsing. See `08-review-packaging.md` Finding 2.

7. **(new) `permission_mode` documented as parsed but absent from
   `HookInput`.** `06-real-codex-testing.md` says permit0 ignores it
   today and treats it as forward-compat capacity, but `HookInput` at
   `crates/permit0-cli/src/cmd/hook.rs:252-274` does not list it.
   Forward-compat works only because there's no
   `#[serde(deny_unknown_fields)]`. See
   `07-review-real-codex-testing.md` Finding 2.

8. **(new) `.gitignore` "no rule needed" claim is fragile.** Plan
   relies on scripts always writing to `/tmp/...`, but
   `PERMIT0_TRACE_DIR` is overridable to a repo-relative path. See
   `08-review-packaging.md` Finding 5.

9. **(new) Plan mixes "to do" and "already done" without
   indicators.** Every Change in 07-packaging.md describes work that
   is already on disk under `integrations/permit0-codex/` (untracked
   in git, but present). Reviewers reading top-to-bottom will miss
   that the right question is "did the existing implementation match
   these intents?" See `08-review-packaging.md` Finding 6.

10. **(new) "Documentation updates needed" checklist mixes done with
    TODO.** `06-real-codex-testing.md` lists 4 items as "needed";
    item 1 (`codex_hooks` → `hooks`) is already done. See
    `07-review-real-codex-testing.md` Finding 3.

11. **(new) README is 184 lines, plan says "< 80 lines."** Cosmetic
    delta: the bound is too tight; the README content is appropriate.
    See `08-review-packaging.md` Finding 3.

12. **(prior) Test 8 (`codex_output_never_contains_allow`) only
    covers `codex_output` in isolation.** The new `hook_output_to_codex`
    function does cover the previously-uncovered shadow and unknown-
    rewrite paths transitively, but the test of the no-allow invariant
    has not been extended to assert the property end-to-end through
    the binary. See `05-review-testing.md` Finding 1.

13. **(prior) "Codex 0.110+" version claim was not citation-backed.**
    Now superseded by 06's verified-against-0.130.0-alpha.5 data;
    legacy version pin in 03-configuration.md should still be
    refreshed. See `04-review-configuration.md` Finding 3.

Plus several nits on header conventions, manual-test ownership, and
discoverability of the dev-test-rig.

## Statistics

| Metric | Count (cumulative) |
|--------|-------|
| Plan docs reviewed | 8 |
| Critical findings | 2 (both addressed in implementation; closed) |
| Major findings | 5 (3 new, 2 still-open from prior) |
| Minor findings | 13 (8 new, 5 still-open) |
| Nits | 9 |
| Verified claims | 50+ |
| Open questions | 26 |

(Counts span all eight per-doc reviews. Critical findings from the
prior review are now closed because the merged implementation
addresses them.)

## Recommendation

**Proceed with implementation as-is for the integration code; clean
up the two new docs before committing the
`integrations/permit0-codex/` tree.** Specifically:

1. **Before `git add integrations/permit0-codex/`:** fix Finding 4
   (auth.json symlink target) and Finding 1 (README table format).
   Both are localized changes (one line in `codex-demo`, three lines
   in `integrations/README.md`).

2. **Before merging `07-packaging.md`:** address Findings 2 (add the
   `--uninstall` flag or drop the claim), 5 (defensive `.gitignore`
   rules), and 6 (mark which Changes are "done" vs "TODO"). These are
   five-minute edits that bring the doc in line with the on-disk
   state.

3. **Before merging `06-real-codex-testing.md`:** soften the cleanup
   recipe (Finding 1 of `07-review-real-codex-testing.md`) and add
   `permission_mode` to `HookInput` (Finding 2). The latter is also
   a five-line code change.

4. **Outstanding from prior review (no new doc covers them):** the
   v1-scope contradiction on session-aware remote mode (Major #4
   above) and the contradictory network-sandbox guidance (Major #5)
   should be resolved before the docs ship to external users.

The implementation has caught up with — and in places improved on —
the original plan. The remaining work is documentation hygiene, not
core engineering.
