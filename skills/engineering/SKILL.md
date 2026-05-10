---
name: engineering
description: >-
  Write production-grade code with high engineering quality. Applies SOLID,
  YAGNI, DRY, and fail-closed principles, follows the repo's conventions,
  and holds a high bar on correctness, testing, and backward compatibility.
  Use when writing code, implementing features, fixing bugs, or making any
  changes to the permit0 codebase.
---

# Engineering Standards for permit0

## When to Use

Use this skill whenever you write or modify code in the permit0 repository.
This applies whether you are implementing a plan from `docs/plans/`, fixing
a bug, adding a feature, or refactoring.

## Workflow

### If implementing from a plan

1. Read every file in `docs/plans/<feature>/` in numbered order. Pay special
   attention to `02-implementation.md` (what to change), `04-testing.md`
   (what to test), and `05-limitations.md` (what NOT to build).
2. Read the existing code you will modify and its neighbors. Understand the
   current patterns before adding to them.
3. Implement change by change, following the plan's numbered list.
4. Write every test described in the testing doc.
5. Run the full CI check locally (see Verification below).

### If working without a plan

1. Read the files you will modify. Understand the current type signatures,
   traits, module structure, and test style.
2. Make minimal, focused changes. Do not refactor or reorganize code outside
   the scope of the task.
3. Write tests for every new behavior and every error path.
4. Run the full CI check locally (see Verification below).

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

Depend on abstractions, not concretions. The CLI layer depends on
`Engine::get_permission()`, not on the internal scoring implementation.
New code must maintain these boundaries -- do not reach across crate
layers to access internals.

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

permit0's security invariant: when in doubt, deny. Every error path,
every panic guard, every unexpected value must result in a safe outcome
(deny or ask), never a silent allow. If your code has a catch-all that
returns allow, that is a security bug.

### 9. No Silent Behavior Changes

Existing behavior must not change unless explicitly intended. If you
rename a field, add a variant, or change a default, verify that every
existing test still passes with the same assertions. If a test needs
updating, confirm the behavior change is intentional.

---

## permit0 Codebase Conventions

Follow these exactly. They are enforced by CI.

### Rust

- `#![forbid(unsafe_code)]` in every crate (except `permit0-py` and
  `permit0-node` which need FFI).
- Edition 2024, MSRV 1.85.
- `max_width = 100` (rustfmt.toml).
- `thiserror` for library crate errors, `anyhow` for CLI/binary errors.
- `proptest` for property-based tests where applicable.
- `RUSTFLAGS="-D warnings"` -- all warnings are fatal. Do not suppress
  warnings with `#[allow(...)]` unless there is a documented reason.
- Prefer `&str` over `String` in function parameters. Own only when
  you must.

### Tests

- Unit tests go in `#[cfg(test)] mod tests` inside the source file.
- Integration tests go in `crates/<crate>/tests/`.
- Test names describe the behavior, not the implementation:
  `codex_output_deny_produces_envelope` not `test_deny`.
- Every public-facing behavior gets at least one test. Every error path
  gets a test.
- Use `assert_eq!` with both expected and actual values. Use `assert!`
  only for boolean conditions. Always include a failure message for
  non-obvious assertions.

### Error Handling

- Library crates: return `Result<T, CrateError>` with `thiserror`.
- CLI: use `anyhow::Result` and `.context("what was happening")`.
- Never `unwrap()` in non-test code. Use `expect("reason")` only when
  the invariant is structurally guaranteed (e.g. after a check that
  ensures the value is `Some`).
- Log errors to stderr with `eprintln!` in the hook path; use `tracing`
  in the daemon path.

### Naming

- Enum variants: PascalCase (`ClientKind::Codex`).
- Functions: snake_case (`derive_session_id`).
- Constants: SCREAMING_SNAKE_CASE (`REPLAY_BATCH_MAX`).
- Test functions: snake_case describing the scenario
  (`strips_mcp_double_underscore_prefix`).
- Serde renames: use `#[serde(rename = "camelCase")]` or
  `#[serde(alias = "...")]` to match wire formats. Do not let Rust
  naming leak into JSON.

---

## Verification

Run the full CI check locally before declaring work complete:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

Fix every warning and every failure. Do not leave broken CI for the user.

---

## Implementation Checklist

Before declaring the work complete, verify:

### Correctness
- [ ] Every intended change is implemented.
- [ ] No unintended changes to files outside the task scope.
- [ ] Deferred/out-of-scope work is not implemented.

### Quality
- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo nextest run --workspace` passes.
- [ ] Every new public function/type has a doc comment.
- [ ] No `unwrap()` in non-test code.
- [ ] No `#[allow(dead_code)]` on new code.

### Tests
- [ ] New code has at least 1 test per public function.
- [ ] Error paths are tested.
- [ ] Edge cases are covered.
- [ ] All existing tests still pass unchanged.

### Security
- [ ] Every error path results in deny or ask, never silent allow.
- [ ] No new wildcard match arms that return allow.
- [ ] Untrusted input (session IDs, tool names, parameters) is treated
      as opaque -- no path traversal, no injection surface.

### Backward Compatibility
- [ ] Existing behavior and public APIs are unchanged unless the task
      explicitly requires it.
- [ ] All existing tests pass with their original assertions.

---

## Common Mistakes to Avoid

### 1. Implementing pseudocode literally

Plan docs and examples show simplified code for readability. The actual
implementation must handle error cases, serde attributes, trait bounds,
and edge cases the snippet omits. Read the surrounding code to understand
the real patterns.

### 2. Adding dead code for the future

Do not stub out features that aren't needed yet, add empty match arms,
or create types with `#[allow(dead_code)]`. Implement what is needed now.

### 3. Changing existing test assertions

If an existing test fails after your change, the change is likely wrong --
not the test. Verify the behavior change is intentional before updating
any test assertion.

### 4. Ignoring the formatter

Run `cargo fmt --all` after every logical group of changes. Do not
accumulate formatting debt and fix it at the end.

### 5. Wide-scope changes to "clean up"

Do not refactor, rename, or reorganize code outside the task scope. Even
if you see an obvious improvement, leave it alone. The change should
contain exactly what was asked for and nothing else.
