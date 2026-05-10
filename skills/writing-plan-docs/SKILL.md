---
name: writing-plan-docs
description: >-
  Write planning documents for new features, integrations, or significant
  changes. Use when the user asks to plan, design, spec, or write a plan
  for a new feature, integration, or architectural change.
---

# Writing Plan Docs

For repo-specific paths, conventions, and architecture, read
[context.md](../context.md).

## When to Use

Use this skill when the user asks you to plan a new integration, a new
module, or any multi-step change that benefits from upfront design before
code.

## Where to Place Plans

```
docs/plans/<feature-name>/
  00-overview.md
  01-protocol.md          (if wire format / API contract exists)
  02-implementation.md
  03-configuration.md     (if user-facing setup is needed)
  04-testing.md
  05-limitations.md
```

- **Path:** Always under `docs/plans/<feature-name>/`.
- **Numbering:** Prefix with `00-` through `0N-` for reading order.
- **Naming:** Use lowercase-kebab-case for the feature directory.

## Documents to Write

Not every plan needs all six docs. Pick the ones that apply.

### 00-overview.md (always required)

The entry point. A reader should understand what, why, and how far after
reading only this file.

Cover:

1. **Goal** -- What this feature does, in one paragraph. If it replicates an
   existing feature, say so and link to the reference implementation.
2. **Data flow** -- ASCII or mermaid diagram showing the end-to-end path.
3. **Comparison table** -- If a similar feature exists, a side-by-side table
   of what is the same and what differs.
4. **Scope** -- Bullet list of what is in v1 vs deferred to v2+.
5. **Dependencies** -- Which modules/packages are touched and which are not.

Header template:

```markdown
# 00 -- <Feature>: Overview and Architecture

**Status:** Draft
**Depends on:** None
**Blocks:** 01-protocol, 02-implementation
```

### 01-protocol.md (when there is a wire format)

Exact schemas for any JSON, TOML, HTTP, or stdin/stdout contract.

Cover:

1. **Input schema** -- Every field, type, whether always present or optional.
2. **Output schema** -- Every possible response shape. Show concrete examples
   for each outcome.
3. **Mapping table** -- How internal types map to the external system's values.
4. **Error handling matrix** -- What happens on crash, timeout, malformed
   output, transport failure. Table format works well.
5. **Session / identity extraction** -- Where session IDs come from, fallback
   chain.
6. **Future extensions** -- Schemas or hooks that exist in the external system
   but are not used in v1.

### 02-implementation.md (always required)

The code-level plan. A developer should know exactly which files to touch
and what to add after reading this.

Cover:

1. **Changes** -- Numbered list of specific code changes. Include the file
   path and a snippet showing the type or function signature.
2. **Files changed vs not changed** -- Table format. Explicitly listing files
   NOT changed is important in well-layered architectures.
3. **Key decisions** -- If there were architectural choices (new file vs extend
   existing, new variant vs new trait impl), state the decision and the
   reasoning in one sentence.
4. **Migration path** -- What existing users need to do (usually nothing).
5. **Risk assessment** -- What breaks if this goes wrong, what the blast
   radius is.

### 03-configuration.md (when user-facing setup exists)

Step-by-step guide a user follows to enable the feature.

Cover:

1. **Prerequisites** -- What to install, build, or configure first.
2. **Step-by-step** -- Numbered steps with copy-pasteable config snippets.
3. **Configuration variants** -- One subsection per mode or deployment option.
4. **Environment variable overrides** -- Table of env vars, what they
   override, and example values.
5. **Verification** -- How to confirm the feature works end-to-end.

Important: use **absolute paths** in examples. Note when `~` does not expand.

### 04-testing.md (always required)

Cover:

1. **Unit tests** -- List each test by name with a one-line description and
   a code snippet showing the assertion. Group by concern.
2. **Regression tests** -- Explicit list of existing tests that must still
   pass unchanged.
3. **Integration tests** -- Commands that exercise the feature end-to-end
   and assert outputs.
4. **Manual test script** -- A script a developer can run interactively.
5. **Edge case matrix** -- Table of scenarios and expected behavior (timeout,
   large input, missing fields, service down, etc.).

### 05-limitations.md (when there are known gaps)

Cover:

1. **v1 limitations** -- Each limitation gets its own subsection with:
   - **Problem**: What does not work.
   - **v1 workaround**: What the user sees instead.
   - **Impact**: How bad is it (low/medium/high).
   - **Risk**: What happens if a developer accidentally hits this.
2. **Future work** -- Versioned roadmap (v2, v3) with one paragraph per item
   describing the approach, not just the goal.

## Document Metadata

Every doc should open with:

```markdown
**Status:** Draft | Review | Approved
**Depends on:** <list of docs that must be read/written first>
**Blocks:** <list of docs that depend on this one>
```

## Dependency Order

Write docs in dependency order. The typical graph:

```
00-overview (first)
  +-> 01-protocol
  +-> 02-implementation (depends on 00 + 01)
        +-> 03-configuration
        +-> 04-testing
  01-protocol +-> 05-limitations
  02-implementation +-> 05-limitations
```

## Research Before Writing

Before writing any plan doc:

1. **Read the reference implementation** if one exists. Understand the
   existing I/O protocol, not just the core logic.
2. **Research the external system's docs.** Use web search. Read the actual
   schema, not just summaries. Pay attention to what is supported vs "parsed
   but not implemented."
3. **Identify the critical difference.** Most similar features share 90% of
   the flow. Find the 10% that differs and make that the focus of the plan.

## Style

- No emojis in plan docs.
- Use tables for comparisons and matrices.
- Use fenced code blocks with the language tag.
- Keep each doc under 300 lines. If it grows beyond that, split.
- Link to source files using relative paths from the doc location.
