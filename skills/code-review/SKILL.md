---
name: code-review
description: >-
  Perform a thorough code review of implemented changes. Reads the plan docs,
  walks the full codebase, then reviews the changed code for correctness,
  security, conventions, testing, and systemic impact. Writes a review doc
  to docs/code-reviews/. Use when the user asks to review code, review an
  implementation, check whether changes are correct, or audit code quality.
---

# Code Review

For repo-specific paths, conventions, and architecture, read
[context.md](../context.md).

## When to Use

Use this skill after code has been written -- either from a plan in
`docs/plans/<feature>/` or from any other task. The review assesses the
implementation against the plan (if one exists), the codebase conventions,
and engineering best practices.

Output is written to:

```
docs/code-reviews/<feature>/<reviewer-id>/review.md
```

Generate `<reviewer-id>` automatically by running `uuidgen | head -c 8`
at the start of the review. This prevents parallel reviewers from
overwriting each other.

## Workflow

### Phase 1: Understand the Intent

If a plan exists at `docs/plans/<feature>/`:
- Read every plan doc in order.
- Note the intended changes, the files that should and should not be
  modified, the deferred scope, and the expected tests.

If no plan exists:
- Read the commit messages, PR description, or ask the user what the
  changes are supposed to do.

### Phase 2: Read the Full Codebase Context

Do NOT review the changed files in isolation. Read the surrounding code
to understand context:

1. **The changed files** -- read each modified file in full, not just the
   diff. Understand what was there before and what is there now.
2. **Direct dependencies** -- if the change adds a call to `foo()`, read
   `foo()`'s implementation. If the change implements a trait, read the
   trait definition and other implementors.
3. **Callers and consumers** -- if the change modifies a public function
   or type, find every call site. Check whether callers still work with
   the new signature or behavior.
4. **Adjacent modules** -- read sibling files in the same directory. Look
   for patterns the change should follow but doesn't, or conventions it
   breaks.
5. **Tests** -- read existing tests for the changed modules. Check whether
   the new code is covered and whether existing tests still make sense.
6. **Crate boundaries** -- if the change crosses crate boundaries (e.g.
   CLI calling engine internals), flag it.

### Phase 3: Review at Two Levels

#### Level 1: Line-by-Line (Local Correctness)

For each changed file, check:

- **Logic errors** -- off-by-one, wrong comparison, missing negation,
  swapped arguments, incorrect type coercion.
- **Error handling** -- does every fallible operation have proper error
  handling? Are errors propagated or silently swallowed? Does the error
  path produce a safe outcome (deny/ask, not silent allow)?
- **Edge cases** -- empty input, null/None, maximum values, unicode,
  concurrent access, timeout.
- **Resource management** -- file handles closed, locks released,
  connections returned to pool.
- **Naming** -- do new names follow the codebase conventions? Are they
  precise and unambiguous?
- **Serde correctness** -- do `#[serde(...)]` attributes match the wire
  format? Are aliases, renames, defaults, and skip conditions correct?
- **Dead code** -- is anything added but never called? Any
  `#[allow(dead_code)]`?

#### Level 2: Big Picture (Systemic Impact)

Step back from the diff and ask:

- **Architectural fit** -- does the change respect crate boundaries? Does
  it put logic in the right layer (CLI vs engine vs store)?
- **Backward compatibility** -- will existing users, configs, or API
  consumers break? Are wire formats changed in a way that old clients
  can't handle?
- **Security** -- does the change introduce a new attack surface? Can
  untrusted input reach a dangerous operation? Is the fail-closed
  invariant maintained?
- **Performance** -- does the change add work to the hot path? Any new
  allocations, clones, or I/O in a loop?
- **Concurrency** -- if the code is async or multi-threaded, are there
  race conditions, deadlocks, or ordering assumptions?
- **Testing gaps** -- is there new behavior without tests? Are edge cases
  from the plan's testing doc covered? Would a property test be
  appropriate?
- **Test quality** -- do existing and new tests assert meaningful
  behavior? Would they catch a real regression, or would they pass even
  if the code was broken? Watch for tests that assert on incidental
  details (string formatting) instead of semantic outcomes.
- **Public API surface** -- do new public types and functions form a
  coherent API that a consumer would understand? Are doc comments
  accurate and sufficient? Does changed behavior have updated docs?
- **Convention drift** -- does the change introduce a new pattern where
  an existing pattern should have been followed? (e.g. a new error type
  when the crate already uses `thiserror`, or manual JSON when `serde`
  should be used.)
- **Ripple effects** -- does the change affect other features that share
  the same code path? Modifying a shared deserialization struct or a public
  function signature affects every consumer, not just the one being added.
- **Plan fidelity** -- if a plan exists, does the implementation match
  it? Are there deviations? Are deferred items accidentally implemented?
  Are planned changes missing?

### Phase 4: Write the Review

Write a single `review.md` file with all findings.

## Review Doc Format

```markdown
# Code Review: <feature or change description>

**Reviewer:** Cursor Agent (<reviewer-id>)
**Review date:** <date>
**Plan:** `docs/plans/<feature>/` (or "No plan")
**Files reviewed:** <list of files read during the review>

## Verdict

One of: APPROVE | APPROVE WITH COMMENTS | REQUEST CHANGES | REJECT

## Executive Summary

3-5 sentences: what the implementation does, whether it achieves its
goal, and the most important finding.

## Findings

### <F1>: <short title>

**Severity:** Critical | Major | Minor | Nit
**File:** `<path>` (lines N-M)
**Issue:** <what is wrong or could be improved>
**Evidence:** <code snippet or reasoning>
**Recommendation:** <specific fix>

### <F2>: ...

## Systemic Assessment

### Architectural Fit
<1-2 paragraphs on whether the change is in the right place>

### Security
<1-2 paragraphs on security implications, or "No new attack surface">

### Backward Compatibility
<1 paragraph on whether existing behavior is preserved>

### Testing Coverage
<1 paragraph on whether tests are adequate, with specific gaps if any>

## What Was Done Well

Bulleted list of things the implementation got right. Good reviews are
balanced -- acknowledging quality work builds trust and calibrates the
reviewer's judgment for the reader.

## Verified Correctness

List of specific claims or behaviors you verified by reading the code.
This is your proof-of-work showing the review was thorough.

- [ ] <thing you checked> -- confirmed in `<file>:<line>`
- [ ] <thing you checked> -- confirmed in `<file>:<line>`
```

## Severity Definitions

| Severity | Meaning | Action required |
|----------|---------|-----------------|
| Critical | Security hole, data loss, silent failure bypass, or crash in production. | Must fix before merge. |
| Major | Incorrect behavior, missing error handling, untested code path, or convention violation that would cause bugs. | Should fix before merge. |
| Minor | Imprecise naming, suboptimal but correct logic, missing doc comment, minor convention drift. | Fix at author's discretion. |
| Nit | Style preference, whitespace, comment wording. | Optional. |

## Review Standards

### Correctness over style

A correct function with imperfect naming is better than a beautifully
named function with a logic error. Prioritize findings that affect
behavior, then security, then conventions, then style.

### Specific over vague

Every finding must cite a file and line range. "The error handling could
be better" is not a finding. "In `foo.rs:42`, the `Err` arm silently
returns a default value instead of propagating the error" is a finding.

### Actionable over opinionated

Each finding should include a concrete recommendation. "Consider using
a different approach" is not actionable. "Replace the `_` wildcard arm
with an explicit match arm for the new variant" is actionable.

### Thorough over fast

Read every changed file in full. Read every caller of every changed
function. Read every test. If you skip a file, you will miss a bug.
A review that finds only nits probably didn't look hard enough.

### Balanced over adversarial

Include a "What Was Done Well" section. If the implementation is clean,
say so. If it follows the plan precisely, note that. Reviewers who only
find flaws lose credibility and discourage authors from seeking review.

## What a Good Review Looks Like

A good review:
- Catches at least one logic or security issue, or explains why there
  are none (with evidence).
- Verifies the change against callers, not just in isolation.
- Confirms test coverage for new behavior and error paths.
- Notes any plan deviation (intentional or accidental).
- Takes a position (approve/request changes) with reasoning.

A bad review:
- Only finds nits and style issues.
- Reviews the diff without reading the surrounding code.
- Restates what the code does without assessing whether it is correct.
- Proposes an alternative design without showing a defect in the current
  one.
