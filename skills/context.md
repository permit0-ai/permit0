# Repository Context: permit0

This file contains repo-specific conventions, paths, and domain knowledge
that the skills under `skills/` reference. The skills themselves are
generic; this file makes them specific to permit0.

When a skill says "read the repo context," it means this file.

## Language and Toolchain

- **Language:** Rust (Edition 2024, MSRV 1.85)
- **Build:** `cargo build --workspace`
- **Test runner:** `cargo nextest run --workspace` (CI) or `cargo test --workspace`
- **Lint:** `cargo clippy --workspace --all-targets -- -D warnings`
- **Format:** `cargo fmt --all` / `cargo fmt --all --check`
- **Supply-chain audit:** `cargo deny check`
- **CI flag:** `RUSTFLAGS="-D warnings"` -- all warnings are fatal.

## Codebase Conventions

### Safety

- `#![forbid(unsafe_code)]` in every crate (except `permit0-py` and
  `permit0-node` which need FFI).

### Error Handling

- Library crates: return `Result<T, CrateError>` with `thiserror`.
- CLI/binary crates: use `anyhow::Result` and `.context("what was happening")`.
- Never `unwrap()` in non-test code. Use `expect("reason")` only when
  the invariant is structurally guaranteed.
- Log errors to stderr with `eprintln!` in the hook path; use `tracing`
  in the daemon path.

### Testing

- Unit tests go in `#[cfg(test)] mod tests` inside the source file.
- Integration tests go in `crates/<crate>/tests/`.
- Test names describe the behavior, not the implementation:
  `output_deny_produces_envelope` not `test_deny`.
- `proptest` for property-based tests where applicable.

### Naming

- Enum variants: PascalCase.
- Functions: snake_case.
- Constants: SCREAMING_SNAKE_CASE.
- Test functions: snake_case describing the scenario.
- Serde renames: use `#[serde(rename = "camelCase")]` or
  `#[serde(alias = "...")]` to match wire formats. Do not let Rust
  naming leak into JSON.

### Formatting

- `max_width = 100` (rustfmt.toml).
- Do not suppress warnings with `#[allow(...)]` unless there is a
  documented reason.

## Architecture

permit0 is a deterministic, rule-based permission framework for AI agent
tool calls. The decision pipeline is pure Rust with no LLM in the hot path.

### Crate Hierarchy

```
permit0-types       (shared types)
permit0-dsl         (YAML DSL: schema, conditions, helpers)
permit0-normalize   (NormalizerRegistry trait + DslNormalizer)
permit0-scoring     (hybrid risk scoring)
permit0-session     (session context + block rules)
permit0-store       (Store trait, SQLite, audit chain)
permit0-token       (Biscuit capability tokens)
permit0-agent       (LLM reviewer for MEDIUM-tier calls)
permit0-engine      (Engine + EngineBuilder -- assembles the pipeline)
permit0-cli         (clap CLI: check / hook / serve / pack / calibrate)
permit0-ui          (axum HTTP server + admin dashboard)
permit0-py          (PyO3 bindings)
permit0-node        (napi-rs bindings)
permit0-shell-dispatch (shell command analysis)
```

### Security Invariant

**Fail closed:** unknown actions route to human review, not auto-allow.
Every error path must produce deny or ask, never silent allow.

### Key Paths

- Packs: `packs/<owner>/<name>/` (normalizers + risk rules + tests)
- Profiles: `profiles/*.profile.yaml`
- Calibration corpus: `corpora/calibration/*.yaml`
- Reference pack: `packs/permit0/email/`
- CLI hook adapter: `crates/permit0-cli/src/cmd/hook.rs`
- Daemon: `crates/permit0-cli/src/cmd/serve.rs`
- Engine: `crates/permit0-engine/src/engine.rs`
- Plans: `docs/plans/<feature>/`
- Plan reviews: `docs/plan-reviews/<feature>/`
- Code reviews: `docs/code-reviews/<feature>/`

### Domain Concepts

- **Pack:** Extension unit with normalizer YAML + risk rule YAML.
- **Normalizer:** Maps a `RawToolCall` to a `NormAction` (canonical action).
- **Risk rule:** Declares flags + amplifiers for an action type.
- **Profile:** Scoring overlay (YAML in `profiles/`) that adjusts weights and thresholds.
- **Calibration:** Testing the engine against a golden corpus.
- **Shadow mode:** Log decisions without enforcing.

### Verification Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo run -- calibrate test
cargo run -- pack validate packs/permit0/email
```
