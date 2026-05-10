---
name: engineering
description: >-
  Write production-grade code with high engineering quality. Applies SOLID,
  YAGNI, DRY, and fail-closed principles, and holds a high bar on
  correctness, testing, and backward compatibility. Use when writing code,
  implementing features, fixing bugs, or making any codebase changes.
---

# Engineering Standards

For repo-specific conventions (language, toolchain, naming, formatting,
verification commands), read [context.md](../context.md).

## When to Use

Use this skill whenever you write or modify code. This applies whether you
are implementing a plan from `docs/plans/`, fixing a bug, adding a feature,
or refactoring.

## Workflow

### If implementing from a plan

1. Read every file in `docs/plans/<feature>/` in numbered order. Pay special
   attention to the implementation doc (what to change), the testing doc
   (what to test), and the limitations doc (what NOT to build).
2. Read the existing code you will modify and its neighbors. Understand the
   current patterns before adding to them.
3. Implement change by change, following the plan's numbered list.
4. Write every test described in the testing doc.
5. Run the full CI check locally (see [context.md](../context.md) for commands).

### If working without a plan

1. Read the files you will modify. Understand the current type signatures,
   traits, module structure, and test style.
2. Make minimal, focused changes. Do not refactor or reorganize code outside
   the scope of the task.
3. Write tests for every new behavior and every error path.
4. Run the full CI check locally (see [context.md](../context.md) for commands).

---

## Engineering Principles

These are non-negotiable. Every line of code you write must satisfy them.

### 1. Single Responsibility (SRP)

Every function, struct, and module does one thing. If a function parses
input AND evaluates policy AND serializes output, split it.

Litmus test: can you describe what the function does without using "and"?

### 2. Open/Closed (OCP)

Extend behavior by adding new variants, not by modifying existing branches.
Adding a new enum variant is correct; cramming new behavior into an existing
arm is wrong.

When adding an enum variant, exhaustive match ensures the compiler tells
you every site that needs updating. Never add a wildcard `_` arm to
silence the compiler -- handle each variant explicitly.

### 3. Liskov Substitution (LSP)

New implementations must honor the contract of the abstraction they
implement. If you implement a trait, uphold every documented invariant.
If a function's doc says it returns exactly N bytes, it must return
exactly N bytes -- not N+1, not "approximately N."

### 4. Interface Segregation (ISP)

Don't force callers to depend on things they don't use. If a struct has
10 fields but a consumer only needs 3, consider whether the struct should
be split or the consumer should take a smaller type. When extending a
shared type with new optional fields, ensure existing callers are
unaffected.

### 5. Dependency Inversion (DIP)

Depend on abstractions, not concretions. New code must maintain crate
and module boundaries -- do not reach across layers to access internals.

### 6. YAGNI (You Aren't Gonna Need It)

Implement exactly what is needed, nothing more. Do not stub out future
features, add empty match arms for hypothetical variants, or build
abstractions "in case we need them later." Dead code is a maintenance
burden and a false signal to readers.

### 7. DRY (Don't Repeat Yourself)

Extract shared logic into functions. If two code paths do the same
transformation, factor it out. But do not over-abstract -- two similar
but distinct operations should stay separate rather than being forced
through a single parameterized function that is harder to read.

### 8. Fail Closed

When in doubt, choose the safe default. Every error path, every panic
guard, every unexpected value must result in a safe outcome, never a
silent pass-through. If your code has a catch-all that silently succeeds,
that is a bug.

### 9. No Silent Behavior Changes

Existing behavior must not change unless explicitly intended. If you
rename a field, add a variant, or change a default, verify that every
existing test still passes with the same assertions. If a test needs
updating, confirm the behavior change is intentional.

---

## Implementation Checklist

Before declaring the work complete, verify:

### Correctness
- [ ] Every intended change is implemented.
- [ ] No unintended changes to files outside the task scope.
- [ ] Deferred/out-of-scope work is not implemented.

### Quality
- [ ] All lint and format checks pass (see [context.md](../context.md)).
- [ ] All tests pass.
- [ ] Every new public function/type has a doc comment.
- [ ] No dead code or suppressed warnings on new code.

### Tests
- [ ] New code has at least 1 test per public function.
- [ ] Error paths are tested.
- [ ] Edge cases are covered.
- [ ] All existing tests still pass unchanged.

### Security
- [ ] Every error path results in a safe outcome, never a silent pass-through.
- [ ] No new wildcard match arms that silently succeed.
- [ ] Untrusted input is treated as opaque -- no path traversal, no
      injection surface.

### Backward Compatibility
- [ ] Existing behavior and public APIs are unchanged unless the task
      explicitly requires it.
- [ ] All existing tests pass with their original assertions.

---

## Common Mistakes to Avoid

### 1. Implementing pseudocode literally

Plan docs and examples show simplified code for readability. The actual
implementation must handle error cases, serialization attributes, trait
bounds, and edge cases the snippet omits. Read the surrounding code to
understand the real patterns.

### 2. Adding dead code for the future

Do not stub out features that aren't needed yet, add empty match arms,
or create types that are never used. Implement what is needed now.

### 3. Changing existing test assertions

If an existing test fails after your change, the change is likely wrong --
not the test. Verify the behavior change is intentional before updating
any test assertion.

### 4. Ignoring the formatter

Run the formatter after every logical group of changes. Do not accumulate
formatting debt and fix it at the end.

### 5. Wide-scope changes to "clean up"

Do not refactor, rename, or reorganize code outside the task scope. Even
if you see an obvious improvement, leave it alone. The change should
contain exactly what was asked for and nothing else.
