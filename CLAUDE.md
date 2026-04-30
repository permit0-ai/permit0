# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build --workspace
cargo build --release --workspace

# Test (CI uses nextest)
cargo nextest run --workspace
cargo test --workspace

# Run a single test
cargo nextest run -p permit0-engine <test_name>
cargo test -p permit0-scoring -- scorer::tests::more_flags_higher_score

# Lint (warnings are errors)
cargo clippy --workspace --all-targets -- -D warnings

# Format
cargo fmt --all
cargo fmt --all --check

# Supply-chain audit
cargo deny check

# Calibration tests (run after changing packs or profiles)
cargo run -- calibrate test
cargo run -- calibrate test --corpus corpora/calibration --profile fintech

# Pack testing
cargo run -- pack test packs/stripe
cargo run -- pack validate packs/stripe

# Start admin dashboard
cargo run -- serve --ui --port 9090
```

`RUSTFLAGS="-D warnings"` is set in CI; all warnings are fatal.

### Python bindings (`permit0-py`)

The Python bindings crate is excluded from `default-members`, so `cargo build` (no flags) skips it. Two ways to build it:

```bash
# Canonical: build + install editable wheel into the active Python env
cd crates/permit0-py
maturin develop                # uses whichever Python `maturin` resolves to

# Plain cargo (also works thanks to .cargo/config.toml on macOS)
cargo build --workspace        # builds every crate including permit0-py
cargo build -p permit0-py      # builds permit0-py only
```

macOS notes:
- `.cargo/config.toml` adds `-undefined dynamic_lookup` for `aarch64-apple-darwin` and `x86_64-apple-darwin` so PyO3's `extension-module` cdylib links without a libpython.
- If both a conda env and a `.venv` are active, maturin refuses with a dual-env error — `unset VIRTUAL_ENV` (or `unset CONDA_PREFIX`) to disambiguate.

## Architecture

permit0 is a deterministic, rule-based permission framework for AI agent tool calls. There is **no LLM in the hot path** — the decision pipeline is pure Rust.

### Crate Dependency Hierarchy

```
permit0-types          (shared types: NormAction, Permission, RiskScore, Tier, RawToolCall)
    ↓
permit0-dsl            (YAML DSL: schema structs, condition evaluator, closed helper registry)
permit0-normalize      (NormalizerRegistry trait + DslNormalizer impl)
permit0-scoring        (6-step hybrid scoring: compute_hybrid(), ScoringConfig, RiskTemplate)
permit0-session        (SessionContext, session amplifier, built-in block rules)
permit0-store          (Store trait → InMemoryStore / SqliteStore; audit chain + signer)
permit0-token          (Biscuit capability tokens)
permit0-agent          (LlmClient trait, AgentReviewer for MEDIUM-tier calls, BootstrapPipeline)
    ↓
permit0-engine         (Engine + EngineBuilder — assembles everything into the decision pipeline)
    ↓
permit0-cli            (clap CLI: check / hook / gateway / serve / pack / calibrate / audit)
permit0-ui             (axum HTTP server + web admin dashboard)
permit0-py             (PyO3 bindings)
permit0-node           (napi-rs bindings)
```

### Decision Pipeline (`Engine::get_permission`)

1. **Normalize** — `RawToolCall` → `NormAction` via `NormalizerRegistry` (YAML packs, highest priority wins)
2. **Denylist** — `norm_hash` hit → immediate `Deny`
3. **Allowlist** — `norm_hash` hit → immediate `Allow`
4. **Policy cache** — repeated `norm_hash` returns cached `Permission`
5. **Unknown action** — no matching risk rule → `HumanInTheLoop` (conservative default), cached
6. **Risk scoring** — `execute_risk_rules` builds a `RiskTemplate`; `session_amplifier_score` + `execute_session_rules` + built-in session block rules update it; `compute_hybrid` produces a `RiskScore`
7. **Tier routing** — Minimal/Low → Allow, High → HumanInTheLoop, Critical → Deny; `blocked=true` → always Deny
8. **Agent review** — Medium tier with a configured `AgentReviewer` calls an LLM; verdict is Deny or HumanInTheLoop; result cached
9. **Audit** — every decision writes a `DecisionRecord` to the store; if audit sink + signer configured, also appends a hash-chained `AuditEntry`

### Pack System

Packs are the extension unit: `packs/<name>/` contains `pack.yaml`, `normalizers/*.yaml`, and `risk_rules/*.yaml`.

- **Normalizer YAML** — matches a `RawToolCall` (by tool name and parameter conditions) and maps it to a `NormAction` with `action_type` (`domain.verb`), `channel`, and typed `entities`.
- **Risk rule YAML** — bound to one `action_type`; declares a base `RiskTemplate` (flags + amplifier values 0–30) and ordered `rules`/`session_rules` that mutate the template. A `gate:` halts evaluation and forces CRITICAL.
- **Closed helpers** — `compute:` fields in normalizers call pure Rust functions registered in `permit0-dsl/src/helpers/`; the set is fixed at compile time.

### Scoring Config & Profiles

`ScoringConfig` (in `permit0-scoring`) holds flag weights, amplifier weights, block rules, and tanh constant. It is the only thing that changes between base / fintech / healthtech profiles.

`profiles/*.profile.yaml` declares multiplier adjustments, threshold shifts, and additional block rules on top of the base config. Guardrails enforced at load time:
- Weight multipliers: 0.5×–2.0×
- Threshold shifts: ±10%
- Cannot touch immutable flags (DESTRUCTION, PHYSICAL, EXECUTION)

### Key Types (`permit0-types`)

| Type | Purpose |
|------|---------|
| `RawToolCall` | Input: tool name + JSON parameters |
| `NormAction` | Normalized action: `action_type`, `domain`, `verb`, `channel`, `entities`, `norm_hash` |
| `RiskScore` | Output of scorer: `raw` (0–1), `tier`, `blocked`, `flags`, `block_reason` |
| `Permission` | `Allow \| Deny \| HumanInTheLoop` |
| `DecisionRecord` | Persisted decision summary (SQLite row or memory) |
| `AuditEntry` | Full tamper-proof audit record with hash chain + ed25519 signature |

### Storage

`Store` trait (in `permit0-store`) provides: `save_decision`, `denylist_add/check`, `allowlist_add/check`, `policy_cache_get/set/invalidate`. Two impls: `InMemoryStore` (default in tests) and `SqliteStore` (`~/.permit0/permit0.db` in production).

Audit trail is separate from the `Store`: `AuditSink` trait with `StdoutSink` and `MemorySink` implementations; `AuditSigner` uses ed25519-dalek. Each `AuditEntry` includes the SHA-256 of the previous entry (`prev_hash`) to form the chain.

### Golden Corpus

`corpora/calibration/*.yaml` — 60 fixture files covering Stripe payments, Bash commands, Gmail, and unknown tools. Always run `cargo run -- calibrate test` after modifying packs or profiles.

### Rust Conventions

- All crates: `#![forbid(unsafe_code)]`
- Edition 2024, MSRV 1.85
- `max_width = 100` (rustfmt.toml)
- `thiserror` for library errors, `anyhow` for CLI/binary errors
- `proptest` for property-based tests (see `permit0-scoring/tests/property_tests.rs`)
