# permit0

Deterministic, fine-grained permission framework for AI agents.

permit0 intercepts every tool call an agent makes, evaluates its risk through a structured scoring pipeline, and returns one of three decisions: **Allow**, **Human-in-the-loop**, or **Deny**.

## Features

- **Deterministic risk scoring** — rule-based pipeline, not LLM-driven policy evaluation
- **YAML DSL** — define normalizers and risk rules without writing Rust
- **Three-layer calibration** — base engine, domain profiles (fintech, healthtech), org-level policy
- **Session-aware** — cumulative amount tracking, attack chain detection, temporal anomaly patterns
- **Compliance-grade audit** — hash chain + ed25519 signatures, signed bundle export
- **Capability tokens** — Biscuit-based bearer tokens, offline-verifiable
- **Polyglot** — Rust core with Python (PyO3) and TypeScript (napi-rs) bindings

## Quick Start

```bash
# Score a tool call
echo '{"tool":"http","arguments":{"method":"POST","url":"https://api.stripe.com/v1/charges","body":{"amount":5000}}}' | permit0 check

# Run pack tests
permit0 pack test packs/stripe/

# Start the approval UI
permit0 ui serve --port 8080
```

## Architecture

```
Agent → normalize (YAML pack) → risk score (YAML rules) → decision → capability token
                                       ↑
                              three-layer calibration
                          (base → domain → org policy)
```

See [docs/permit.md](docs/permit.md) for the full design and [docs/dsl.md](docs/dsl.md) for the YAML DSL specification.

## Project Structure

```
crates/
├── permit0-types       # shared types (Tier, Permission, NormAction, RiskScore)
├── permit0-scoring     # risk scoring math (compute_hybrid, guardrails)
├── permit0-normalize   # Normalizer trait, NormalizerRegistry
├── permit0-dsl         # YAML DSL parser, interpreter, closed helpers
├── permit0-engine      # orchestrator (get_permission pipeline)
├── permit0-token       # Biscuit capability tokens
├── permit0-session     # session context, aggregation, temporal patterns
├── permit0-store       # Store trait, SQLite/Postgres implementations
├── permit0-agent       # LLM agent reviewer (Human/Deny only)
├── permit0-ui          # axum + React approval dashboard
└── permit0-cli         # CLI binary
packs/                  # first-party YAML packs (bash, gmail, stripe)
profiles/               # domain calibration profiles (fintech, healthtech)
```

## Building

```bash
cargo build --workspace
cargo nextest run --workspace
```

## License

Apache-2.0
