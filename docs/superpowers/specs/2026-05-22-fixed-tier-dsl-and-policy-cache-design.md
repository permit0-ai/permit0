# Fixed `tier:` in the risk-rule DSL + policy-cache invalidation

**Date:** 2026-05-22
**Status:** Approved design — ready for implementation plan
**Branch:** `extract-email-mcp`

## 1. Context & problem

A single email delete (`gmail_delete` / `outlook_delete`, normalized to `email.delete`)
was allowed unprompted. Investigation found **two independent defects**:

### Defect A — `email.delete` is mis-scored

`packs/permit0/email/risk_rules/delete.yaml` carries a comment `# default tier: HIGH`,
but the scorer produces:

```
raw 0.1118 → score 11/100 → tier MINIMAL → Permission: ALLOW
```

The hybrid scorer's `base` term is a category-weighted sum of flag weights. A delete
can only honestly carry `MUTATION` (weight 0.10), `GOVERNANCE` (0.14), and arguably
`DESTRUCTION` (0.28). The high-value amplifiers (`destination` 0.155, `sensitivity`
0.136) do not apply. Worked through the formula, the **theoretical ceiling** for a
single delete — every applicable amplifier pinned to 1.0 — is `raw ≈ 0.63`; a
realistic calibration lands at `raw ≈ 0.27` (LOW). HIGH needs `raw > 0.55`.

**Conclusion:** the scoring model cannot honestly express "this action type is
intrinsically HIGH" through flags and amplifiers. The `# default tier: HIGH` comment
was always aspirational. `send.yaml` has the same disconnect (out of scope here).

Compounding this, `corpora/calibration/008-gmail-delete-single.yaml` and
`021-outlook-delete-single.yaml` assert `expected_tier: Minimal` — the repo's golden
corpus currently *blesses* the wrong behavior, contradicting the pack comment.

### Defect B — the policy cache froze the verdict and skipped scoring

The exact deleted message re-checked returns:

```json
{"permission":"allow","action_type":"email.delete","source":"PolicyCache"}
```

`source: PolicyCache` with **no `score`, no `tier`** — pipeline step 4 short-circuited
steps 5–8. `policy_cache` is keyed only by `norm_hash → permission`, with **no TTL and
no invalidation when packs/profiles change**. Once any `norm_hash` is decided, the
verdict is permanent; fixing the pack would not affect already-cached entries. The
cache also discards the `RiskScore`, so cache hits are blind in `/api/v1/check` and
the audit log.

(`norm_hash` does include the `message_id`, so caching is per-message — but each entry,
once written, never expires or re-evaluates.)

## 2. Goals & non-goals

**Goals**

1. A single `email.delete` resolves to **HIGH → human-in-the-loop**; bulk delete
   (>10 messages) resolves to **CRITICAL → Deny**.
2. The risk-rule DSL gains a first-class way to declare a tier directly, instead of
   only deriving it from a computed score.
3. The policy cache invalidates when scoring config changes, ages entries out via
   TTL, and preserves the `RiskScore` for observability.

**Non-goals**

- Recalibrating the hybrid scorer's weights/constants (`constants.rs`).
- Fixing the `send.yaml` "default tier: HIGH" disconnect (one-line follow-up once
  `tier:` exists).
- Changing the cache's keying to be session-aware (TTL is the chosen mitigation).
- A `min_tier` score-floor — explicitly dropped in favor of a direct `tier:`
  (YAGNI; can be added later if a concrete need appears).

## 3. Design — Part A: fixed `tier:` in the risk-rule DSL

A risk rule becomes one of two kinds:

- **Scored rule** (unchanged): `base` flags + amplifiers → `compute_hybrid` → tier.
- **Fixed-tier rule** (new): declares `tier:` directly; the scoring path is bypassed.

### 3.1 Schema

`RiskRuleDef` (`crates/permit0-dsl/src/schema/risk_rule.rs`):

- Add `tier: Option<String>`.
- Make `base: Option<RiskBaseDef>` (currently required).

Example fixed-tier rule:

```yaml
permit0_pack: "permit0/email"
action_type: "email.delete"
tier: high                        # scoring bypassed; this IS the tier
base:
  flags:                          # optional — audit/UI labels only
    MUTATION: primary
    GOVERNANCE: secondary
session_rules:
  - when: { record_count: { gt: 10 } }
    then:
      - gate: "bulk delete — known cover-up vector"   # → CRITICAL
```

### 3.2 Semantics

- `tier:` accepts `minimal | low | medium | high`. **`critical` is rejected** —
  forcing CRITICAL/Deny is what `gate:` is for.
- When `tier:` is set:
  - `base.amplifiers`, if present, is a **validation error** (fail loud — amplifiers
    are meaningless without scoring).
  - `base.flags` is kept and carried into `RiskScore.flags` for audit/UI display.
  - `rules` / `session_rules` may contain **only `gate:`** mutations. `add_flag`,
    `upgrade`, `downgrade`, `override`, `promote_flag`, `remove_flag`, `split` are
    validation errors (there is no score to mutate).
- Gates still fire: a `gate:` on a fixed-tier rule escalates to CRITICAL exactly as
  on a scored rule.
- `RiskScore` for a fixed-tier hit:
  - `tier` = the declared tier.
  - `raw` / `score` = the tier band's midpoint, so UI and audit show a coherent
    number: minimal→0.075/8, low→0.25/25, medium→0.45/45, high→0.65/65.
  - `flags` = flags from `base.flags` (if any).
  - `reason` = `"fixed tier (pack-declared): <tier>"`.
  - `blocked` = false (unless a gate fired → CRITICAL via the existing path).

### 3.3 Implementation path

- `crates/permit0-scoring/src/template.rs` — `RiskTemplate` gains
  `fixed_tier: Option<Tier>`.
- `crates/permit0-dsl/src/risk_executor.rs` — when building the template from a
  `RiskRuleDef` with `tier:`, set `template.fixed_tier`; apply only `gate:`
  mutations from `rules`/`session_rules`.
- `crates/permit0-scoring/src/scorer.rs` — `compute_hybrid`: after the existing
  step 1 blocked/gate check, if `t.fixed_tier` is `Some`, return the fixed-tier
  `RiskScore` and skip steps 2–6. This ordering guarantees gates still win.
- `crates/permit0-dsl/src/pack_validate.rs` (and/or `validate.rs`) — enforce the
  rules in §3.2.

### 3.4 Applied to `email.delete`

`packs/permit0/email/risk_rules/delete.yaml` is rewritten as the §3.1 example:
`tier: high`, flags retained for audit, bulk-delete `session_rule` switched from
score mutations to a `gate:`. One file covers gmail + outlook (shared `email.delete`).

**Outcome:** single delete = HIGH → HITL prompt; bulk delete (>10) = CRITICAL → Deny.

Editing the file invalidates `packs/permit0/email/pack.lock.yaml`; it must be
regenerated with `permit0 pack lock packs/permit0/email`.

## 4. Design — Part B: policy-cache invalidation + TTL

The engine already declines to cache `HumanInTheLoop`, so the cache only ever holds
`Allow` / `Deny`.

### 4.1 Schema

`policy_cache` rows (both `policy_state_sqlite.rs` and `pg_state.rs`):

```
policy_cache(norm_hash, permission, risk_score_json, config_fingerprint, created_at)
```

### 4.2 Config fingerprint

A SHA-256 computed once at engine build time over:

- the sorted set of pack lockfile digests (covers all pack content),
- the active profile's YAML bytes (or a sentinel when no profile),
- a `SCORING_MODEL_VERSION` constant (bumped by hand when `constants.rs` changes).

Anything that can change a verdict changes this hash.

### 4.3 Invalidation — startup clear-if-changed

The engine loads packs only at startup (no hot reload), so invalidation is tied to
restart:

1. Persist the fingerprint in a small `cache_meta(key, value)` table.
2. On engine boot, compare the stored fingerprint to the current one.
3. On mismatch: `policy_cache_clear()`, then store the new fingerprint.

An unchanged restart keeps the cache warm. (Alternative considered: fingerprint as a
composite key column — more robust across mixed engine versions, heavier API change.
Rejected for simplicity.)

### 4.4 TTL

`policy_cache_get` additionally filters `created_at > now − ttl`. TTL is configurable
via `PERMIT0_POLICY_CACHE_TTL_SECS`, **default 3600 (1 hour)**. Rationale: verdicts
can depend on session context (velocity / session amplifier) that `norm_hash` does
not capture; a short TTL bounds that staleness. Expired rows are deleted lazily on
read plus a periodic sweep.

### 4.5 Observability

`policy_cache_set` stores the `RiskScore` as `risk_score_json`; `policy_cache_get`
returns it. The engine returns this on a cache hit so `/api/v1/check` and the audit
log show real `tier` / `score` instead of a blank.

`PolicyState` trait changes (`crates/permit0-store/src/policy_state.rs`), updated in
all three impls (`policy_state_memory.rs`, `policy_state_sqlite.rs`, `pg_state.rs`):

- `policy_cache_get` → `Option<CachedDecision>` where
  `CachedDecision { permission, risk_score: Option<RiskScore> }`.
- `policy_cache_set` → takes `risk_score`, `config_fingerprint`, `created_at`.
- Add cache-meta accessors for the stored fingerprint.

`crates/permit0-engine/src/engine.rs` — pass the `RiskScore` into `policy_cache_set`;
surface it from the cache hit in step 4; run the startup fingerprint reconciliation.
`crates/permit0-cli/src/engine_factory.rs` — compute the fingerprint at build time.

## 5. Testing

- `corpora/calibration/008-gmail-delete-single.yaml` and `021-outlook-delete-single.yaml`
  → `expected_tier: High`, `expected_permission: HumanInTheLoop`.
- New corpus case: bulk delete (>10 messages) → `expected_tier: Critical`,
  `expected_permission: Deny`.
- DSL unit tests: `tier:` parsing; rejection of `critical`, of `amplifiers` alongside
  `tier:`, and of non-`gate:` mutations on fixed-tier rules; fixed-tier `RiskScore`
  shape (band-midpoint `raw`, flags carried).
- Scorer test: `compute_hybrid` honors `fixed_tier`; a gate still overrides it to
  CRITICAL.
- Store tests: TTL expiry, fingerprint-change clears the cache, `risk_score_json`
  round-trips, cache-meta persists.
- `cargo run -- calibrate test` green.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`.

## 6. Rollout

The fix has **no effect on the running system** until:

1. `permit0 pack lock packs/permit0/email` — regenerate the lockfile after editing
   `delete.yaml`.
2. Rebuild the `permit0-engine` Docker image — packs are **baked into the image**
   (`PERMIT0_PACKS_DIR=/etc/permit0/packs`), not bind-mounted.
3. One-time `DELETE FROM policy_cache` on the `permit0_state` Postgres DB — the 25
   existing rows predate the fingerprint column (includes the live `email.delete`
   entry and two fake-id rows left by diagnosis). After this, the fingerprint logic
   maintains the cache automatically.

## 7. Risks & open questions

- **Bulk delete → CRITICAL/Deny** is stricter than today's score-based escalation.
  Consistent with the "cover-up vector" intent; revisit if auto-deny proves too
  aggressive (could instead be a second fixed-tier `split` or left at HIGH).
- **TTL vs session-sensitivity:** caching by `norm_hash` alone ignores session
  context. TTL (1h default) bounds the staleness but does not eliminate it; a
  session-aware cache key is a deliberate non-goal here.
- **`SCORING_MODEL_VERSION`** is a manual constant — a missed bump after editing
  `constants.rs` would leave stale cache entries until TTL expiry. Acceptable;
  documented next to the constant.

## 8. Change inventory

| Area | Files |
|------|-------|
| DSL schema | `crates/permit0-dsl/src/schema/risk_rule.rs` |
| DSL executor | `crates/permit0-dsl/src/risk_executor.rs` |
| DSL validation | `crates/permit0-dsl/src/pack_validate.rs`, `validate.rs` |
| Scorer | `crates/permit0-scoring/src/template.rs`, `scorer.rs` |
| Store trait + impls | `crates/permit0-store/src/policy_state.rs`, `policy_state_memory.rs`, `policy_state_sqlite.rs`, `pg_state.rs` |
| Engine | `crates/permit0-engine/src/engine.rs` |
| Engine factory | `crates/permit0-cli/src/engine_factory.rs` |
| Pack | `packs/permit0/email/risk_rules/delete.yaml`, `pack.lock.yaml` |
| Corpus | `corpora/calibration/008-gmail-delete-single.yaml`, `021-outlook-delete-single.yaml`, new bulk-delete case |
