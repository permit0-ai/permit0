---
name: revising-plan-docs
description: >-
  Revise planning documents based on design review feedback. Reads review
  docs, critically assesses each finding (agree or disagree with reasoning),
  then edits the plan docs accordingly or explains why no change is needed.
  Use when the user asks to revise, update, address feedback, or incorporate
  review comments into plan docs in the permit0 repository.
---

# Revising Plan Docs for permit0

## When to Use

Use this skill after plan reviews have been written to
`docs/plan-reviews/<feature>/`. The input is the review docs. The output is
direct edits to the plan docs at `docs/plans/<feature>/` -- or an explicit
explanation of why a finding was rejected.

There is no separate output document. The plan docs themselves are the
deliverable.

## Workflow

### Phase 1: Read the Reviews

Read every reviewer subdirectory under `docs/plan-reviews/<feature>/`.
Each subdirectory (e.g. `review-a/`, `review-b/`) is one reviewer's
output. Read each in order, starting with `00-summary.md`. For each
finding, note:

- The severity (Critical / Major / Minor / Nit).
- The specific claim the reviewer disputes.
- The evidence the reviewer cites (file paths, line numbers).
- The reviewer's recommendation.

If multiple reviewers submitted reviews (different `Reviewer:` lines), read
all of them. Note where reviewers agree and where they conflict.

### Phase 2: Critically Assess Each Finding

For every finding, do your own independent analysis. Do NOT blindly accept
or reject -- verify against the codebase yourself.

For each finding, reach one of three verdicts:

**AGREE** -- The reviewer is correct. The plan has a real problem.
- State what you verified in the code that confirms the finding.
- Edit the plan doc to fix it.

**DISAGREE** -- The reviewer is wrong or the finding is not actionable.
- State what you verified in the code that contradicts the finding.
- Explain to the user why the plan is correct as-is. Do not edit the plan.

**PARTIALLY AGREE** -- The reviewer identified a real issue but the
recommendation is wrong or disproportionate.
- State which part is valid and which is not.
- Edit the plan doc with your alternative fix.

Rules for critical assessment:

1. **Never agree just because the reviewer said so.** Read the actual code.
   Reviewers make mistakes -- they may misread a function signature, miss a
   serde attribute, or confuse two similar types.
2. **Never disagree just to preserve the plan.** If the reviewer found a
   real bug (e.g. a wire-format mismatch between two components), the plan
   must be fixed regardless of how much work it creates.
3. **Severity matters.** Critical and Major findings must be addressed with
   code-level verification. Minor and Nit findings can be accepted on face
   value if they are obviously correct (typos, naming, etc.).
4. **Conflicting reviewers require a tiebreak.** If reviewer A says the plan
   is wrong and reviewer B says it is correct, you must verify independently
   and pick a side with evidence.

### Phase 3: Act on Each Finding

Process findings in severity order (Critical first, Nits last).

For each finding, do one of:

- **Edit the plan doc** -- Make the change directly with StrReplace. Keep
  edits minimal and targeted. Do not rewrite sections unaffected by the
  finding. Add a `**Revised:** <date>` line to the metadata header of any
  doc you modify.

- **Do nothing and explain why** -- Tell the user your verdict, what you
  checked, and why the plan stands. This is a normal outcome -- not every
  finding warrants a change.

There is no Phase 4. No revision log, no summary doc. The edits (or lack
of edits) plus your explanations to the user are the complete output.

## Handling Multiple Reviewers

When multiple review sets exist (e.g. from parallel agents):

1. Read all review sets before making any changes.
2. Group findings by topic, not by reviewer. Two reviewers may flag the
   same issue differently.
3. When reviewers agree on a finding, fix it once.
4. When reviewers conflict, state both positions, your independent
   assessment, and which side you took.

## What to Change vs What Not to Change

### DO change the plan when:

- A code snippet does not match the current function signature or type
  definition in the codebase.
- The plan claims a file is not modified but evidence shows it must be.
- The plan omits an error case or failure mode that the reviewer identified
  with concrete evidence.
- The plan's JSON schema does not match the actual wire format.
- A test in the testing doc would not compile or tests the wrong thing.

### DO NOT change the plan when:

- The reviewer suggests an alternative design without evidence that the
  current design is wrong. Design preferences are not defects.
- The reviewer flags a future concern that the plan explicitly defers to v2.
- The reviewer found a purely stylistic nit that does not affect correctness.
- The reviewer disagrees with a documented decision without showing it causes
  a concrete problem.
