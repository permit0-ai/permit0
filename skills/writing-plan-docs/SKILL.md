---
name: writing-plan-docs
description: >-
  Write planning documents for new permit0 features, integrations, or
  significant changes. Use when the user asks to plan, design, spec, or
  write a plan for a new integration, pack, feature, or architectural
  change in the permit0 repository.
---

# Writing Plan Docs for permit0

## When to Use

Use this skill when the user asks you to plan a new integration (e.g. a new
agent host like Codex, Cursor, CrewAI), a new pack, a new crate, or any
multi-step change that benefits from upfront design before code.

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
   existing integration, say so and link to the reference implementation.
2. **Data flow** -- ASCII or mermaid diagram showing the end-to-end path.
3. **Comparison table** -- If a similar feature exists (e.g. Claude Code
   integration), a side-by-side table of what is the same and what differs.
4. **Scope** -- Bullet list of what is in v1 vs deferred to v2+.
5. **Crate dependencies** -- Which crates are touched and which are not.
   permit0's architecture makes most features crate-local; call that out.

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
2. **Output schema** -- Every possible response shape. Show concrete JSON
   examples for each verdict/outcome.
3. **Mapping table** -- How permit0 types (`Permission`, `Tier`, etc.) map
   to the external system's values.
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
   path and a Rust/TS/Python snippet showing the type or function signature.
2. **Files changed vs not changed** -- Table format. Explicitly listing files
   NOT changed is important in permit0 because most features are I/O-layer
   changes with no engine/scoring/pack impact.
3. **Key decisions** -- If there were architectural choices (new file vs extend
   existing, new enum variant vs trait impl), state the decision and the
   reasoning in one sentence.
4. **Migration path** -- What existing users need to do (usually nothing).
5. **Risk assessment** -- What breaks if this goes wrong, what the blast
   radius is.

### 03-configuration.md (when user-facing setup exists)

Step-by-step guide a user follows to enable the feature.

Cover:

1. **Prerequisites** -- What to install, build, or configure first.
2. **Step-by-step** -- Numbered steps with copy-pasteable config snippets.
   Show both JSON and TOML if the external system supports both.
3. **Configuration variants** -- One subsection per mode (local, remote,
   session-aware, shadow, calibration, project-local, with-profile).
4. **Environment variable overrides** -- Table of env vars, what they
   override, and example values.
5. **Verification** -- How to confirm the integration works end-to-end.

Important: use **absolute paths** in examples. Note when `~` does not expand.

### 04-testing.md (always required)

Cover:

1. **Unit tests** -- List each test by name with a one-line description and
   a code snippet showing the assertion. Group by concern (parsing, output
   serialization, session ID, edge cases).
2. **Regression tests** -- Explicit list of existing tests that must still
   pass unchanged.
3. **Integration tests** -- Shell commands that pipe input through the binary
   and assert stdout/exit code.
4. **Manual test script** -- A `scripts/test-<feature>.sh` that a developer
   can run interactively.
5. **Edge case matrix** -- Table of scenarios and expected behavior (timeout,
   large input, missing fields, daemon down, etc.).

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

Start with `00-overview` and `01-protocol` (can be parallel), then
`02-implementation`, then `03-configuration` / `04-testing` / `05-limitations`
(can be parallel).

## Research Before Writing

Before writing any plan doc:

1. **Read the reference implementation** if one exists. For integrations,
   read `crates/permit0-cli/src/cmd/hook.rs` (the Claude Code hook) end to
   end. Understand the existing I/O protocol, not just the engine.
2. **Research the external system's hook/plugin docs.** Use web search. Read
   the actual schema, not just summaries. Pay attention to what is supported
   vs "parsed but not implemented."
3. **Identify the critical difference.** Most integrations share 90% of the
   flow. Find the 10% that differs and make that the focus of the plan.

## Style

- No emojis in plan docs.
- Use tables for comparisons and matrices.
- Use fenced code blocks for JSON/TOML/Rust with the language tag.
- Keep each doc under 300 lines. If it grows beyond that, split.
- Link to source files using relative paths from the doc location
  (e.g. `[hook.rs](../../../crates/permit0-cli/src/cmd/hook.rs)`).

## Reference Example

The Codex CLI integration plan at `docs/plans/codex-integration/` is the
reference for this skill. Read those files for concrete examples of each
document type.
