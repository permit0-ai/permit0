# Review: 06 — Real Codex CLI Testing: Verified End-to-End

**Reviewer:** Cursor Agent (a7ebc31f)
**Plan doc:** `docs/plans/codex-integration/06-real-codex-testing.md`
**Review date:** 2026-05-10

## Verdict

APPROVE WITH COMMENTS

## Summary

This is the strongest doc in the codex-integration set. It captures
hard-won protocol facts from a live Codex 0.130.0-alpha.5 run, identifies
three concrete schema deltas vs. the original plan, and documents the
trust-model gotcha that would otherwise silently swallow hours of
debugging. It deserves to land. The main concerns are (a) the cleanup
recipe is destructive of unrelated managed config, (b) the
`permission_mode` field is documented as "ignored" but not explicitly
plumbed through `HookInput`, leaving a forward-compat fragility, and
(c) the "documentation updates needed" checklist is partially done
already — the doc should mark which items are still open.

## Detailed Findings

### Finding 1: Cleanup recipe wipes the entire `requirements_toml_base64` key

**Severity:** Major
**Location:** "Reproducing the end-to-end test" Step 6, and the
condensed cleanup at line 91 of
`integrations/permit0-codex/README.md`
**Claim:** `defaults delete com.openai.codex requirements_toml_base64`
removes the permit0 hook.
**Reality:** The `requirements_toml_base64` key is a single base64-
encoded TOML blob that may also contain non-permit0 settings: the
`[hooks]` section's `managed_dir`, other `[[hooks.PreToolUse]]` blocks
from a different team policy, MCP server entries, sandbox preferences,
etc. `defaults delete <key>` removes the entire key, not just the
permit0 portion. Anyone with site-wide MDM or an existing managed-prefs
setup will silently lose all of it. The doc presents this command as
the canonical undo with no warning.
**Recommendation:** Either (a) reframe the recipe to read-modify-write
(decode the existing TOML, strip the permit0 hook block, re-encode), or
(b) add a prominent warning: "This deletes the entire managed-prefs
TOML, including any other Codex settings layered there. If you have
non-permit0 managed config, decode the current value first
(`defaults read com.openai.codex requirements_toml_base64 | base64 -d`),
remove only the permit0 entry, and re-write."

### Finding 2: `permission_mode` is documented as parsed but not in `HookInput`

**Severity:** Minor
**Location:** "Schema corrections" §3 and "Implications for permit0"
bullet "Every behavior I could verify against Codex's actual schemas
matches what permit0 does"
**Claim:** "`permission_mode` is one of:
`default | acceptEdits | plan | dontAsk | bypassPermissions`. permit0
silently ignores it today; this is forward-compat capacity for gating
decisions on Codex's approval policy."
**Reality:** `HookInput` at `crates/permit0-cli/src/cmd/hook.rs:252-274`
declares the existing optional fields explicitly (`session_id`,
`turn_id`, `cwd`, `hook_event_name`, `model`, `tool_use_id`,
`transcript_path`) but does NOT list `permission_mode`. Forward-compat
"works" only because `HookInput` doesn't use
`#[serde(deny_unknown_fields)]`, so unknown keys are silently dropped.
That's fragile in two directions: (a) a future audit/forwarding pass
that wants to round-trip the full Codex envelope will lose
`permission_mode` entirely, and (b) if anyone ever adds
`#[serde(deny_unknown_fields)]` for safety, every Codex 0.130+ payload
will start failing to parse with no obvious connection back to this
doc's "forward-compat" claim.
**Recommendation:** Add `permission_mode: Option<String>` to
`HookInput` with a one-line doc comment ("Captured for forward-compat;
not currently consumed"), the same shape as the other Codex-specific
fields. Then the doc's "ignored today" wording is exactly true and the
field shows up in `build_tool_call_metadata`'s audit forwarding path
(`hook.rs:552`) for free.

### Finding 3: "Documentation updates needed" checklist mixes done with TODO

**Severity:** Minor
**Location:** "Implications for permit0" → "Documentation updates
needed in `03-configuration.md`"
**Claim:** Lists four items as "needed":
1. Replace `codex_hooks = true` → `hooks = true`
2. Add a "Trust model" section
3. Add the `requirements_toml_base64` recipe
4. Note `permission_mode` arrives in stdin
**Reality:** Item 1 is already done (verified via `git diff
docs/plans/codex-integration/03-configuration.md` and a fresh read at
line 41 of 03-configuration.md). The doc presents items 1-4 as a flat
TODO list without indicating completion state, so a reader can't tell
which items still need work.
**Recommendation:** Convert to a checklist with completion markers,
e.g.:
```markdown
- [x] Replace `[features] codex_hooks = true` → `[features] hooks = true` (done in PR #N)
- [x] Add a "Trust model" section
- [x] Add the `requirements_toml_base64` recipe
- [ ] Note that `permission_mode` arrives in stdin and is currently ignored
```
Then close the loop by linking from each finished item to the section
in 03-configuration where the change landed.

### Finding 4: Reproducing instructions hard-code one path; no self-contained alternative

**Severity:** Minor
**Location:** "Reproducing the end-to-end test" Step 1
**Claim:** `cd /Users/ziyou/Development/permit0 && cargo build --release`
**Reality:** This is the original tester's local path, not portable.
Anyone trying to reproduce on their machine has to mentally substitute,
and the rest of the script's use of `/tmp/permit0-codex-test/` (Steps
2-3) is similarly tied to the original scratch dir. The doc is at the
same level of polish as `integrations/permit0-codex/dev-test-rig/`,
but doesn't reference the new dev-test-rig as a more discoverable
"replay this transcript" path.
**Recommendation:** Either (a) replace the absolute path with a `$REPO`
variable + an instruction to set it, or (b) replace the whole "Reproducing"
section with a single line: "See `integrations/permit0-codex/dev-test-rig/`
for the same flow as committed scripts." (Per `07-packaging.md`, the
dev-test-rig is the durable home for these scripts.)

### Finding 5: No CI gate for the live-Codex path

**Severity:** Minor
**Location:** "Tests for CI" subsection
**Claim:** "A real-Codex CI test needs an isolated `CODEX_HOME` with a
managed preferences entry. Doable on a self-hosted runner; impractical
for GitHub Actions (no defaults DB control). Likely defer to a manual
release-gate test."
**Reality:** Reasonable, and the synthetic `scripts/test-codex-hook.sh`
covers most of the wire-format risk. But "manual release-gate test"
needs a process owner: who runs it, on what cadence, and where the
artifact (test transcript, captured stdin/stdout, environment) is
archived. Otherwise the manual test becomes "we tested it once on
2026-05-10 and never again."
**Recommendation:** Add a one-liner under "Tests for CI": "Manual
release-gate owner: <role>. Cadence: every Codex 0.MINOR bump or every
permit0 release that touches `crates/permit0-cli/src/cmd/hook.rs`.
Artifacts: tag the resulting `events.log` and `inv-*/` snapshot with
the Codex version under `docs/code-reviews/codex-integration/<id>/`."

### Finding 6: Status header lacks plan-doc lineage

**Severity:** Nit
**Location:** Header
**Claim:** Header has `**Status:** VERIFIED working against Codex
0.130.0-alpha.5` and `**Verified date:** 2026-05-10`.
**Reality:** Other plan docs use `**Status:** Draft | Review | Approved`
plus `**Depends on:** ...` / `**Blocks:** ...`. The "VERIFIED" status is
informative but breaks the pattern, and there's no `**Blocks:**` line
even though `07-packaging.md`'s header says it depends on this doc.
**Recommendation:** Add `**Blocks:** 07-packaging` and either keep
"VERIFIED working" as the new status (and update other docs to use the
same vocabulary) or relabel as "Approved" with the verified-date line
preserved as proof.

### Finding 7: TUI vs `codex exec` discrepancy could be louder

**Severity:** Nit
**Location:** "Schema corrections" §4 ("Trust model — the operational
gotcha")
**Claim:** Hooks from `~/.codex/config.toml` are silently skipped in
`codex exec`.
**Reality:** Excellent finding, captured cleanly. But the table at the
bottom understates how invisible the failure is — there's no "what to
look for to confirm this is happening" guidance. A user who sees no
hook fires in `codex exec` and no error in `--json` output may waste
hours.
**Recommendation:** Add to the trust-model section: "Diagnostic: run
`RUST_LOG=trace codex exec ...` and grep for `hook` in stderr. If you
see lines like `skipping unverified hook` (or no `hook` lines at all),
the trust model is the cause." Cross-reference to the trust table.

## Verified Claims

- The verified Codex stdin schema (`session_id`, `turn_id`,
  `transcript_path`, `cwd`, `hook_event_name`, `model`,
  `permission_mode`, `tool_name`, `tool_input`, `tool_use_id`) is
  exactly what `HookInput` accepts modulo the unlisted
  `permission_mode` field — confirmed at
  `crates/permit0-cli/src/cmd/hook.rs:252-274`.
- Empty stdout is correctly emitted as zero bytes, not as a trailing
  newline — confirmed at `hook.rs:480-491` (`emit_hook_output` skips
  the println for `OutputFormat::Codex` when `hook_output_to_codex`
  returns `None`).
- The HITL → deny mapping with marker is real — `hook_output_to_codex`
  at `hook.rs:441-471` appends `CODEX_HITL_MARKER` to the reason for
  any `ask` verdict before wrapping in a deny envelope.
- `CODEX_THREAD_ID` is honored as a session-ID source in the Codex
  format branch — `hook.rs:594-614` (`derive_session_id_for_format`).
- The `[features] codex_hooks` → `[features] hooks` migration is
  reflected in `03-configuration.md` lines 30-48 (verified via `git diff`
  and the live file).
- The `scripts/test-codex-hook.sh` 9-case smoke test exists and
  exercises `--client codex` shapes against the binary — verified at
  `/Users/ziyou/Development/permit0/scripts/test-codex-hook.sh:1-187`.
- The `codex exec` "silent hook skip" trust-model gotcha is consistent
  with how `dev-test-rig/codex-demo` writes managed prefs at every
  launch instead of relying on user trust — confirmed at
  `integrations/permit0-codex/dev-test-rig/codex-demo:74-75`.

## Questions for the Author

1. Is there a story for forward-compat when Codex adds new required
   fields to the PreToolUse stdin schema in a future release? Today
   the absence of `#[serde(deny_unknown_fields)]` makes us tolerant,
   but we don't notice when a new field appears — meaning permit0
   could miss security-relevant context (e.g. a future
   `dangerous_action: true` flag). Should there be a logged warning on
   unknown-field detection?
2. Should this doc be moved out of `docs/plans/` into
   `docs/code-reviews/` once it's marked Approved? It's now a verified
   test report rather than a forward-looking plan, and `07-packaging.md`
   already depends on it as a stable reference.
3. Would adding `permission_mode` to the `HookInput` struct
   (Finding 2) be in scope for the implementation PR that landed the
   Codex hook, or a separate follow-up?
4. The "trust model" table lists `cloud_requirements` as "always
   trusted, workspace-managed". Is there an analogous unattended path
   on Linux/Windows worth documenting, or is the macOS managed-prefs
   path the only option for now?
