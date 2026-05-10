---
name: reviewing-plan-docs
description: >-
  Review planning documents by reading the plan docs and doing a thorough
  codebase walkthrough, then writing detailed review docs. Use when the user
  asks to review, audit, critique, or validate a plan, design doc, or spec
  in the permit0 repository.
---

# Reviewing Plan Docs for permit0

## When to Use

Use this skill when the user asks you to review, audit, critique, or validate
planning documents under `docs/plans/<feature>/`. The output is a set of
review docs written to a **reviewer-specific subdirectory**:

```
docs/plan-reviews/<feature>/<reviewer-id>/
```

The `<reviewer-id>` must be unique per agent so that parallel reviewers do
not overwrite each other. **Derive it automatically** -- do not ask the user.

To generate the reviewer ID: run `uuidgen | head -c 8` in a shell to get
an 8-character random hex string (e.g. `a3f1b20c`). Use that as the
subdirectory name. Do this once at the start of the review, before writing
any files.

Example: two parallel reviews of the Codex integration would write to:

```
docs/plan-reviews/codex-integration/a3f1b20c/
docs/plan-reviews/codex-integration/7e42d9f1/
```

## Workflow

### Phase 1: Read the Plan

Read every file in `docs/plans/<feature>/` in numbered order. For each doc,
note:

- What it claims (the design decisions, schemas, code changes).
- What assumptions it makes.
- What it explicitly defers or omits.

### Phase 2: Codebase Walkthrough

Do a thorough read of the actual source code that the plan references. This
is not optional -- you must verify claims against real code.

For integration plans, always read:

1. **The reference implementation** the plan says it is based on. For example,
   if the plan says "replicate the Claude Code integration," read
   `crates/permit0-cli/src/cmd/hook.rs` end to end.
2. **The crate(s) the plan says it will modify.** Read every file in those
   crates, not just the ones the plan mentions.
3. **The crates the plan says are NOT modified.** Spot-check at least the
   public API surface to verify the plan's claim that no changes are needed.
4. **Packs and risk rules** if the feature touches normalization or scoring
   (read `packs/permit0/email/` as the reference pack).
5. **The daemon/serve code** if the feature involves `--remote` mode
   (`crates/permit0-cli/src/cmd/serve.rs`).
6. **Tests** -- read existing test files to understand current coverage and
   what the plan's new tests need to complement.

### Phase 3: Write the Review

Write review docs to `docs/plan-reviews/<feature>/`. One review file per
plan doc, plus a summary.

## Output Structure

```
docs/plan-reviews/<feature>/<reviewer-id>/
  00-summary.md               # Overall verdict and key findings
  01-review-overview.md       # Review of 00-overview.md
  02-review-protocol.md       # Review of 01-protocol.md
  03-review-implementation.md # Review of 02-implementation.md
  04-review-configuration.md  # Review of 03-configuration.md
  05-review-testing.md        # Review of 04-testing.md
  06-review-limitations.md    # Review of 05-limitations.md
```

Each reviewer writes to its own subdirectory. This prevents parallel agents
from overwriting each other's output.

Skip review files for plan docs that don't exist (e.g. if there is no
`01-protocol.md`, skip `02-review-protocol.md`).

## Review Doc Format

Every review doc must follow this structure:

```markdown
# Review: <plan doc title>

**Reviewer:** Cursor Agent (session <timestamp or ID>)
**Plan doc:** `docs/plans/<feature>/<filename>`
**Review date:** <date>

## Verdict

One of: APPROVE | APPROVE WITH COMMENTS | REQUEST CHANGES | REJECT

## Summary

2-3 sentences: what the plan doc gets right, what it gets wrong.

## Detailed Findings

### Finding 1: <short title>

**Severity:** Critical | Major | Minor | Nit
**Location:** <section or line reference in the plan doc>
**Claim:** <what the plan says>
**Reality:** <what the code actually does>
**Recommendation:** <what to change>

### Finding 2: ...

## Verified Claims

List the specific claims you checked against the codebase and confirmed
are correct. This is as important as the findings -- it shows the review
was thorough.

## Questions for the Author

Numbered list of open questions that the reviewer could not resolve by
reading the code.
```

## Summary Doc Format (00-summary.md)

```markdown
# Plan Review Summary: <feature>

**Reviewer:** Cursor Agent (session <timestamp or ID>)
**Review date:** <date>
**Plan location:** `docs/plans/<feature>/`

## Overall Verdict

One of: APPROVE | APPROVE WITH COMMENTS | REQUEST CHANGES | REJECT

## Key Findings

Bulleted list of the most important findings across all review docs,
ordered by severity.

## Statistics

| Metric | Count |
|--------|-------|
| Plan docs reviewed | N |
| Critical findings | N |
| Major findings | N |
| Minor findings | N |
| Nits | N |
| Verified claims | N |
| Open questions | N |

## Recommendation

1-2 paragraphs: should the team proceed with implementation as-is,
or are changes needed first?
```

## Distinguishing Your Review

Multiple agents may review the same plan in parallel. Reviews are kept
separate by writing to different subdirectories (see Output Structure).

Additionally:

1. **Always include the reviewer line:** `**Reviewer:** Cursor Agent
   (<reviewer-id>)` -- use the same hex string as the subdirectory name.
2. **Cite specific file paths and line numbers** from the codebase when
   verifying or disputing claims. Other reviewers may make the same point
   but your evidence trail will differ.
3. **Include a "Verified Claims" section** -- this is your proof-of-work
   showing which parts of the codebase you actually read.

## What Makes a Good Review

### DO

- **Verify every code snippet** in the plan against the actual source.
  Plans often show idealized code that doesn't match current function
  signatures or module structure.
- **Check for missing error handling.** Plans often describe the happy path
  and skip what happens on failure.
- **Validate the "files NOT changed" list.** If the plan claims the engine
  is untouched, confirm no engine changes are actually needed.
- **Look for wire-format mismatches.** If the plan describes a JSON schema
  for communication between two components, verify both sides agree. This is
  where bugs hide (e.g. one side sends `"human"`, the other expects
  `"humanintheloop"`).
- **Check that test coverage matches the claimed behavior.** If the plan
  says "HITL maps to deny," there should be a test for that.
- **Flag implicit assumptions.** If the plan assumes network access in a
  sandboxed environment, call it out.

### DON'T

- Don't rubber-stamp. If you only found nits, you probably didn't read
  deeply enough.
- Don't rewrite the plan. Findings should be specific and actionable, not
  alternative designs.
- Don't skip the codebase walkthrough. A review based only on reading the
  plan docs is not a review -- it's proofreading.

## Severity Definitions

| Severity | Meaning |
|----------|---------|
| Critical | The plan is wrong in a way that would cause a security hole, data loss, or silent governance bypass if implemented as written. |
| Major | The plan has a significant gap or incorrect assumption that would cause bugs or user confusion, but not a security issue. |
| Minor | The plan is imprecise or incomplete in a way that would slow down implementation but not cause defects. |
| Nit | Style, naming, or documentation improvement. |
