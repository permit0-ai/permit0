# Review: 07 — Packaging: Repo Layout and Reusable Artifacts

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/07-packaging.md`
**Review date:** 2026-05-10

## Verdict

APPROVE WITH COMMENTS

## Summary

The packaging plan correctly identifies Codex as a "shape #2" (CLI flag
+ config, no library to publish) integration and proposes a sensible
layout that mirrors `integrations/permit0-openclaw/`. Most of the work
described is **already done on disk** (the `integrations/permit0-codex/`
tree is fully populated but untracked in git), so this doc reads more
like a retroactive specification than a forward-looking plan. The main
issues are: (a) two specific deltas between what the plan promises and
what's already in the tree (README length and `--uninstall` flag), (b)
the `integrations/README.md` table format the plan proposes does not
match the format the existing README uses, (c) the `--shadow` env path
in `dev-test-rig/codex-demo` symlinks `~/.codex/auth.json` into a world-
writable `/tmp/` dir, and (d) the `.gitignore` "no rule needed" claim is
fragile because trace dir is overridable.

## Detailed Findings

### Finding 1: Plan and existing README disagree on `integrations/README.md` table layout

**Severity:** Major
**Location:** Change 4, "Update `integrations/README.md`"
**Claim:** Add Codex to the existing single table:
```markdown
| [`permit0-codex/`](./permit0-codex/) | [OpenAI Codex CLI]... | — (CLI hook) | `permit0 hook --client codex` | PreToolUse hook in `~/.codex/config.toml` |
```
**Reality:** The actual `integrations/README.md` (verified at lines 7-21)
already has a different structure: a primary table for npm-installable
packages (one row, OpenClaw) followed by a separate "CLI-hook
integrations (no separate library; config + docs only)" subsection with
its own three-column table where Codex is currently listed:
```markdown
| Folder | Framework | Hook config lives in |
|---|---|---|
| [`permit0-codex/`](./permit0-codex/) | [OpenAI Codex CLI](...) | `~/.codex/config.toml` `[hooks]` or `~/.codex/hooks.json` |
```
The existing layout is arguably better (CLI-hook integrations are
genuinely a different shape than npm packages), but the plan would
either silently overwrite it or leave both tables stale. The plan's
"move Codex from the Claude-Code-style bullet into the table" instruction
also doesn't apply — Codex is no longer in any "Also supported" bullet.
**Recommendation:** Update Change 4 to reflect what the README already
does: "Codex is already listed in the CLI-hook integrations table at
`integrations/README.md:17-19`. No change needed unless we're
consolidating the two tables." If consolidation is the goal, spell out
what the merged table should look like.

### Finding 2: `--uninstall` flag claimed but not implemented

**Severity:** Minor
**Location:** Change 2, third bullet ("`install-managed-prefs.sh` —
the `defaults write com.openai.codex requirements_toml_base64` recipe
… Includes a `--uninstall` flag to undo.")
**Claim:** The script supports `--uninstall` for one-command teardown.
**Reality:** The committed script at
`integrations/permit0-codex/examples/install-managed-prefs.sh` has no
argument parsing at all (verified by reading lines 1-78). It only
documents the manual command:
```bash
# To uninstall:
#   defaults delete com.openai.codex requirements_toml_base64
```
And the help text at the end repeats the same manual command (lines
71-72). A user who reads the plan and types
`bash install-managed-prefs.sh --uninstall` will get a re-install of
the hook (the script ignores `$@`).
**Recommendation:** Either (a) add the `--uninstall` flag to the
script (a 5-line `case "${1:-}" in --uninstall) defaults delete ... ;;`
addition), or (b) remove the claim from Change 2. The same
`defaults delete` behavior already exists as `dev-test-rig/cleanup`
(verified at `integrations/permit0-codex/dev-test-rig/cleanup`), so
option (a) is genuinely useful for the non-rig install path.

### Finding 3: README is 184 lines, plan says "< 80 lines"

**Severity:** Minor
**Location:** Change 1 ("Short (< 80 lines), user-facing")
**Claim:** The README is < 80 lines.
**Reality:** `integrations/permit0-codex/README.md` is 184 lines
(verified via `wc -l`). The actual file is well-organized and the extra
length is mostly justified (Setup interactive vs unattended, what
permit0 intercepts table, behavior under verdict tiers, file-by-file
listing, code/design pointers), so the bound in the plan is too tight,
not the README too long.
**Recommendation:** Either bump the plan's bound to "< 200 lines" or
drop the line-count constraint. The README is appropriately scoped for
"setup recipe + behavior contract" — cutting it to 80 lines would force
removing the verdict-tier behavior table or the file-by-file listing,
both of which are user-discoverable value.

### Finding 4: `dev-test-rig/codex-demo` symlinks `~/.codex/auth.json` into `/tmp/`

**Severity:** Major
**Location:** Plan Change 3 (`codex-demo` listed as "no path changes
beyond REPO_ROOT") — but the underlying script does more than the plan
implies.
**Claim:** Plan says "Runtime artifacts (events.log, inv-*/,
mock-mcp.log, *.sqlite) continue to write to `/tmp/permit0-codex-test/`
— this keeps the repo clean and `.gitignore` simple. The scripts
discover and create that directory on first run."
**Reality:** `integrations/permit0-codex/dev-test-rig/codex-demo:91-92`
also symlinks `~/.codex/auth.json` and `~/.codex/models_cache.json`
into `$TRACE_DIR` (default `/tmp/permit0-codex-test/`). The auth.json
file contains the user's Codex API session credentials. `/tmp/` is
world-readable on macOS (mode 1777), so any other local user (or
any process running as a different uid) can dereference the symlink
and read the credentials. Even on a single-user dev machine this is a
worse posture than the user's `~/.codex/` (mode 700 by default).
**Recommendation:** Either (a) place the symlinks under
`$HOME/.permit0-codex-trace/` (or another user-private dir) by
default, with `/tmp/permit0-codex-test/` only as an opt-in override,
or (b) add a security note to the plan and to
`integrations/permit0-codex/dev-test-rig/README.md` flagging this.
Option (a) is the safer default; the dev-rig README already mentions
`PERMIT0_TRACE_DIR=...` as an override.

### Finding 5: `.gitignore` "no rule needed" claim is fragile

**Severity:** Minor
**Location:** Change 6 (".gitignore entry" — "No actual ignore rule
needed — the scripts write outside the repo.")
**Claim:** `dev-test-rig/codex-demo` and `wrap-permit0.sh` write to
`/tmp/permit0-codex-test/`, which is outside the repo, so no
`.gitignore` rule is needed.
**Reality:** Both scripts honor `PERMIT0_TRACE_DIR` (verified at
`codex-demo:27` and `wrap-permit0.sh:31`). A user who sets
`PERMIT0_TRACE_DIR=./trace` (or any repo-relative path) will land
`events.log`, `inv-*/`, `mock-mcp.log`, `config.toml`, `auth.json`
symlink, etc. inside the repo. With the plan's "comment-only"
.gitignore, those will all show as untracked changes and risk being
committed. The repo's `.gitignore` (45 lines, verified) has no
fallback rules that would catch them either.
**Recommendation:** Add minimal defensive rules:
```gitignore
# Codex integration dev-test-rig runtime data (override-safe)
**/events.log
**/mock-mcp.log
**/inv-[0-9]*-*/
**/permit0-codex-test/
```
Or, alternatively, change the scripts to refuse to start if
`PERMIT0_TRACE_DIR` resolves to a path inside the repo.

### Finding 6: Plan mixes "to do" and "already done" without indicators

**Severity:** Minor
**Location:** Whole "Changes" section, plus "Acceptance criteria"
**Claim:** Each Change is presented as work to perform.
**Reality:** Verified that all of `integrations/permit0-codex/`
already exists on disk (matched against the plan's layout diagram
line by line: README.md ✓, examples/ {config.toml.example ✓,
hooks.json.example ✓, install-managed-prefs.sh ✓ (without
`--uninstall`)}, dev-test-rig/ {README.md ✓, codex-demo ✓, watch ✓,
cleanup ✓, wrap-permit0.sh ✓, mock-gmail-mcp.py ✓, _watch_render.py
✓}). The plan is descriptive of completed work, not prescriptive.
That's fine, but the Changes / Acceptance Criteria framing is
misleading — a reviewer reading top-to-bottom will think the work is
forthcoming and will miss that the right review question is "did
the existing implementation match these intents?"
**Recommendation:** Add a one-line status under "Status: Draft":
"Implementation status: artifacts on disk under
`integrations/permit0-codex/`; uncommitted (not yet `git add`-ed)."
Then optionally convert each Change to a checkbox: `[x] Created`
with a link to the file, `[ ] Outstanding` only for items still TODO
(per Findings 1, 2, 5).

### Finding 7: `examples/install-managed-prefs.sh` doesn't reference `dev-test-rig/cleanup`

**Severity:** Minor
**Location:** Change 2 implicit, examples/install-managed-prefs.sh
**Claim:** N/A — the plan describes the install script in isolation.
**Reality:** The install script's help text (lines 61-77) tells the
user to uninstall via the manual `defaults delete` command. But the
repo also ships `dev-test-rig/cleanup` (line 1-32, a 32-line script
that does the same thing with status messages). A user installing
via `examples/install-managed-prefs.sh` won't necessarily know to
look in `dev-test-rig/` (which the plan correctly labels as "not for
end users").
**Recommendation:** Mention in the plan (and add to the install
script's help text) that
`integrations/permit0-codex/dev-test-rig/cleanup` provides a friendlier
uninstall, OR (better) move a `cleanup-managed-prefs.sh` into
`examples/` so end users have the symmetric pair without venturing into
the dev rig.

### Finding 8: "5 minute" acceptance criterion is unverifiable

**Severity:** Nit
**Location:** Acceptance criteria, first checkbox
**Claim:** "a user can follow it from zero to a working hook in
< 5 minutes"
**Reality:** This is a subjective benchmark with no defined start
condition (Does "zero" mean no Codex install? No Rust toolchain? No
permit0 checkout?). `cargo build --release` alone takes more than 5
minutes from a cold cache on most machines.
**Recommendation:** Either drop the time bound or make it concrete:
"Starting from a Codex install + a permit0 checkout with
`./target/release/permit0` already built, a user can follow the
README to a working hook in fewer than 10 user-actions (count: copy
TOML, paste TOML, save, run codex, type /hooks, ...)."

### Finding 9: Header `Blocks: None` ignores future v3 plugin packaging

**Severity:** Nit
**Location:** Header, "**Blocks:** None"
**Claim:** Nothing depends on this doc.
**Reality:** The "Deferred" section explicitly mentions a v3 Codex
plugin packaging path (`plugin.toml` for `codex plugin install
permit0`) that would presumably reuse the
`integrations/permit0-codex/` tree this doc establishes. So future
plugin work technically depends on this doc's layout decisions.
**Recommendation:** Either accept "Blocks: None" as "for v1" or
write `**Blocks:** Future Codex plugin packaging (v3, deferred)`.

### Finding 10: No mention of how the `examples/` configs stay in sync with reality

**Severity:** Nit
**Location:** Change 2
**Claim:** Three example files, "each self-contained and
copy-pasteable."
**Reality:** Today the examples reproduce the TOML/JSON shape
verified in `06-real-codex-testing.md`. But there's no mechanism that
breaks if Codex changes the schema or if our hook adds new flags. The
synthetic `scripts/test-codex-hook.sh` tests the binary contract but
doesn't read the examples.
**Recommendation:** Add an acceptance criterion or a follow-up issue:
"Lint job parses each `examples/*.{toml,json}.example` to confirm
syntactic validity and presence of required keys (`[features]`,
`[[hooks.PreToolUse]]`, `command`). Catches drift cheaply."

## Verified Claims

- The `integrations/permit0-openclaw/` directory is the precedent the
  plan references — verified its layout (`src/`, `__tests__/`,
  `package.json`, `README.md`, etc.) at
  `/Users/ziyou/Development/permit0/integrations/permit0-openclaw/`.
- All 11 files the plan lists under "Layout" exist at
  `integrations/permit0-codex/...` — verified via Glob (every plan-listed
  file is present).
- `wrap-permit0.sh` correctly derives `REPO_ROOT` via
  `BASH_SOURCE` walk (lines 27-29 of the actual script), matching the
  plan's intent. Same pattern in `examples/install-managed-prefs.sh`
  (lines 21-23) and `dev-test-rig/codex-demo` (lines 22-23).
- Trace dir override via `PERMIT0_TRACE_DIR` is honored by every
  rig script — `codex-demo:27`, `wrap-permit0.sh:31`, `watch:12`,
  `cleanup:19`, `mock-gmail-mcp.py:26`.
- The `dev-test-rig/codex-demo` script does the right thing for
  unattended trust: writes `requirements_toml_base64` directly via
  `defaults write` at every launch (line 74-75) so the on-disk script
  and the registered hook stay in sync. Matches the trust-model
  guidance in `06-real-codex-testing.md`.
- `scripts/test-codex-hook.sh` exists and is unchanged by this plan
  — verified the file at the documented path; its 9 cases use the
  `--client codex` flag and exercise the same shapes 06 and 07 rely
  on.
- The Codex CLI integration is genuinely a "shape #2" (no library to
  publish) — confirmed by the absence of any `Cargo.toml`,
  `package.json`, or `pyproject.toml` under `integrations/permit0-codex/`,
  unlike `integrations/permit0-openclaw/` which has both
  `package.json` and `package-lock.json`.
- `~/.codex/auth.json` symlinking from `dev-test-rig/codex-demo:91`
  is intentional (login carries over to the isolated `CODEX_HOME`)
  but the plan doesn't address the security trade-off — see
  Finding 4.
- The git status confirms `integrations/permit0-codex/` is untracked
  (verified via `git status integrations/permit0-codex/`), so
  Change 1-4's "create" framing reflects the commit boundary, not
  the on-disk state.

## Questions for the Author

1. Is the plan retroactive (documenting work already done) or
   prescriptive (specifying what to do next)? Current framing is the
   latter, but the on-disk state is the former. See Finding 6.
2. Should `examples/install-managed-prefs.sh` and
   `dev-test-rig/cleanup` converge on a single `manage-prefs.sh
   {install,uninstall,status}` script? Today the install path lives
   in `examples/` (end-user-facing) and the uninstall lives in
   `dev-test-rig/` (contributor-facing), which is the reverse of what
   a non-contributor expects. Finding 7.
3. Is there a Linux story? The plan and 06-real-codex-testing both
   focus exclusively on macOS managed-prefs. If Codex is single-platform
   for now, that's fine, but the doc could say so explicitly.
4. The "Deferred" section mentions Codex's "managed MCP schema
   wasn't resolvable in the 0.130 binary." Is that issue tracked
   somewhere (Codex bug, internal note) so we can revisit it without
   re-discovering the friction?
5. Should `integrations/permit0-codex/dev-test-rig/` ship a
   `Makefile` (or `justfile`) so contributors don't have to remember
   the script names? `make demo` / `make watch` / `make cleanup` is a
   classic ergonomic win for multi-script rigs.
