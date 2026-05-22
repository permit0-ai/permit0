# Fixed `tier:` DSL + Policy-Cache Invalidation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a single `email.delete` resolve to HIGH → human-in-the-loop, and make the policy cache invalidate on config change + age out via TTL.

**Architecture:** Two phases. Phase A adds a fixed `tier:` declaration to the risk-rule DSL — a rule states its tier directly instead of deriving it from a computed score; gates still escalate to CRITICAL. Phase B adds a config fingerprint, TTL, and `RiskScore` storage to the policy cache. The phases are independent; do A then B.

**Tech Stack:** Rust (edition 2024), `serde`/`serde_yaml`, `rusqlite` (SQLite state), `sqlx` (Postgres state), `tokio`, `cargo nextest`.

**Conventions:** All crates are `#![forbid(unsafe_code)]`, `max_width = 100`. Warnings are errors (`-D warnings`). After every task: `cargo fmt --all` then commit.

---

## Reference: how scoring works today

- `compute_hybrid` (`crates/permit0-scoring/src/scorer.rs`) turns a `RiskTemplate` into a `RiskScore`. Step 1 returns CRITICAL if `t.blocked`. Steps 2–6 compute a `raw` score → tier via `TIER_THRESHOLDS`.
- Tier thresholds (`crates/permit0-types/src/risk.rs`): `raw ≤ 0.15` Minimal, `≤ 0.35` Low, `≤ 0.55` Medium, `≤ 0.75` High, else Critical.
- A risk rule (`RiskRuleDef`) has `base` (flags + amplifiers), `rules`, `session_rules`. `risk_executor.rs` builds the `RiskTemplate`; the engine then calls `compute_hybrid`.
- The policy cache (`PolicyState` trait, `crates/permit0-store/src/policy_state.rs`) is keyed by `norm_hash → Permission`. Three impls: `policy_state_sqlite.rs`, `pg_state.rs`, `policy_state_memory.rs`.

---

# Phase A — Fixed `tier:` in the risk-rule DSL

## Task A1: `compute_hybrid` honors `RiskTemplate.fixed_tier`

**Files:**
- Modify: `crates/permit0-scoring/src/template.rs`
- Modify: `crates/permit0-scoring/src/scorer.rs`

- [ ] **Step 1: Add the `fixed_tier` field to `RiskTemplate`**

In `template.rs`, add `use permit0_types::Tier;` to the imports, then add the field to the struct and initialize it in `RiskTemplate::new()`:

```rust
// in struct RiskTemplate, after `children`:
    /// Pack-declared fixed tier. When set, `compute_hybrid` bypasses
    /// score computation and returns this tier directly (gates still win).
    #[serde(default)]
    pub fixed_tier: Option<Tier>,
```

```rust
// in RiskTemplate::new(), inside Self { ... }, after `children: Vec::new(),`:
            fixed_tier: None,
```

- [ ] **Step 2: Write the failing tests in `scorer.rs`**

Add to the `mod tests` block in `crates/permit0-scoring/src/scorer.rs`:

```rust
    #[test]
    fn fixed_tier_short_circuits_scoring() {
        // Flags/amps that would otherwise score MINIMAL.
        let mut t = RiskTemplate::new();
        t.add("MUTATION", permit0_types::FlagRole::Primary);
        t.fixed_tier = Some(Tier::High);
        let config = ScoringConfig::default();
        let score = compute_hybrid(&t, &config, None);
        assert_eq!(score.tier, Tier::High);
        assert!(!score.blocked);
        assert!(score.flags.contains(&"MUTATION".to_string()));
    }

    #[test]
    fn gate_overrides_fixed_tier() {
        // A gate must still escalate to CRITICAL even on a fixed-tier template.
        let mut t = RiskTemplate::new();
        t.fixed_tier = Some(Tier::High);
        t.gate("bulk delete");
        let config = ScoringConfig::default();
        let score = compute_hybrid(&t, &config, None);
        assert_eq!(score.tier, Tier::Critical);
        assert!(score.blocked);
    }
```

- [ ] **Step 3: Run the tests — verify they fail**

Run: `cargo test -p permit0-scoring -- scorer::tests::fixed_tier scorer::tests::gate_overrides`
Expected: FAIL — `fixed_tier` field unknown / wrong tier.

- [ ] **Step 4: Implement the fixed-tier short-circuit**

In `scorer.rs`, add this helper above `compute_hybrid`:

```rust
/// Representative `raw` score for a pack-declared fixed tier — the midpoint
/// of the tier's `TIER_THRESHOLDS` band, so UI/audit show a coherent number.
fn tier_midpoint_raw(tier: permit0_types::Tier) -> f64 {
    use permit0_types::Tier;
    match tier {
        Tier::Minimal => 0.075,
        Tier::Low => 0.25,
        Tier::Medium => 0.45,
        Tier::High => 0.65,
        Tier::Critical => 0.875,
    }
}
```

In `compute_hybrid`, immediately **after** the Step 1 `if t.blocked { ... }` block and **before** the Step 2 block-rules loop, insert:

```rust
    // Fixed-tier short-circuit: a pack-declared `tier:` bypasses scoring.
    // Placed after the blocked/gate check so gates still force CRITICAL.
    if let Some(ft) = t.fixed_tier {
        let raw = tier_midpoint_raw(ft);
        let mut score = to_risk_score(
            raw,
            active_flags,
            &format!("fixed tier (pack-declared): {ft}"),
            false,
            None,
        );
        score.tier = ft;
        return score;
    }
```

Add `use permit0_types::Tier;` to the test module if not already imported (it is — `use permit0_types::Tier;` exists in `mod tests`).

- [ ] **Step 5: Run the tests — verify they pass**

Run: `cargo test -p permit0-scoring`
Expected: PASS (all scorer tests, including the two new ones).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/permit0-scoring/src/template.rs crates/permit0-scoring/src/scorer.rs
git commit -m "feat(scoring): RiskTemplate.fixed_tier bypasses score computation"
```

---

## Task A2: DSL schema — `tier` field and optional `base`

**Files:**
- Modify: `crates/permit0-dsl/src/schema/risk_rule.rs`

- [ ] **Step 1: Write the failing test**

Add a `mod tests` block at the end of `risk_rule.rs` (or extend an existing one):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_tier_rule_without_amplifiers() {
        let yaml = r#"
permit0_pack: "permit0/email"
action_type: "email.delete"
tier: high
base:
  flags:
    MUTATION: primary
session_rules:
  - when: { record_count: { gt: 10 } }
    then:
      - gate: "bulk delete"
"#;
        let rule: RiskRuleDef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.tier.as_deref(), Some("high"));
        let base = rule.base.expect("base present");
        assert_eq!(base.flags.get("MUTATION").map(String::as_str), Some("primary"));
        assert!(base.amplifiers.is_empty());
    }

    #[test]
    fn parses_scored_rule_still() {
        let yaml = r#"
permit0_pack: "permit0/email"
action_type: "email.send"
base:
  flags: { OUTBOUND: primary }
  amplifiers: { scope: 18 }
"#;
        let rule: RiskRuleDef = serde_yaml::from_str(yaml).unwrap();
        assert!(rule.tier.is_none());
        assert!(rule.base.is_some());
    }
}
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cargo test -p permit0-dsl -- risk_rule::tests`
Expected: FAIL — `tier` field unknown / `base` is not `Option`.

- [ ] **Step 3: Modify the schema**

In `risk_rule.rs`, change `RiskRuleDef` and `RiskBaseDef`:

```rust
/// A risk rule YAML file — defines how an action_type is scored.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskRuleDef {
    pub permit0_pack: String,
    pub action_type: String,
    /// Pack-declared fixed tier (`minimal|low|medium|high`). When set, the
    /// scoring path is bypassed; see `risk_executor`. Mutually informs
    /// validation (see `validate.rs`).
    #[serde(default)]
    pub tier: Option<String>,
    /// Base flags + amplifiers. Required for scored rules; optional for
    /// fixed-tier rules (where `flags` are kept only as audit labels).
    #[serde(default)]
    pub base: Option<RiskBaseDef>,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub session_rules: Vec<SessionRuleDef>,
}

/// Base risk template definition.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskBaseDef {
    #[serde(default)]
    pub flags: HashMap<String, String>,
    #[serde(default)]
    pub amplifiers: HashMap<String, i32>,
}
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cargo test -p permit0-dsl -- risk_rule::tests`
Expected: PASS. (The crate will not yet *build* fully — `risk_executor.rs` still passes `&rule_def.base`. That is fixed in Task A3. Run the test with `--no-fail-fast` is not needed; the test module compiles, but `cargo test -p permit0-dsl` as a whole will fail to compile until A3. Proceed to A3 before committing.)

- [ ] **Step 5: Do NOT commit yet** — combined commit with Task A3 (the crate must build).

---

## Task A3: `risk_executor` — optional base + set `fixed_tier`

**Files:**
- Modify: `crates/permit0-dsl/src/risk_executor.rs`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `risk_executor.rs`:

```rust
    #[test]
    fn fixed_tier_rule_sets_template_fixed_tier() {
        let yaml = r#"
permit0_pack: "permit0/email"
action_type: "email.delete"
tier: high
base:
  flags: { MUTATION: primary }
session_rules:
  - when: { record_count: { gt: 10 } }
    then:
      - gate: "bulk delete"
"#;
        let rule_def: RiskRuleDef = serde_yaml::from_str(yaml).unwrap();
        let template = execute_risk_rules(&rule_def, &json!({}), None);
        assert_eq!(template.fixed_tier, Some(permit0_types::Tier::High));
        assert_eq!(template.flags.get("MUTATION"), Some(&FlagRole::Primary));

        // Bulk-delete session gate still fires.
        let mut t2 = execute_risk_rules(&rule_def, &json!({}), None);
        execute_session_rules(&rule_def, &mut t2, &json!({"record_count": 50}));
        assert!(t2.blocked);
    }
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cargo test -p permit0-dsl -- risk_executor::tests::fixed_tier`
Expected: FAIL to compile — `build_base` takes `&RiskBaseDef`, not `Option`.

- [ ] **Step 3: Implement**

In `risk_executor.rs`:

Add a tier parser near the top (after the `use` lines):

```rust
/// Parse a DSL tier string into a `Tier`. Returns `None` for unrecognised
/// values — callers should have validated the string first.
pub fn parse_tier(s: &str) -> Option<permit0_types::Tier> {
    use permit0_types::Tier;
    match s.to_ascii_lowercase().as_str() {
        "minimal" => Some(Tier::Minimal),
        "low" => Some(Tier::Low),
        "medium" => Some(Tier::Medium),
        "high" => Some(Tier::High),
        "critical" => Some(Tier::Critical),
        _ => None,
    }
}
```

Change `build_base` to accept an `Option`:

```rust
/// Build template from an optional base definition.
fn build_base(base: Option<&crate::schema::risk_rule::RiskBaseDef>) -> RiskTemplate {
    let mut template = RiskTemplate::new();
    let Some(base) = base else {
        return template;
    };
    for (flag, role_str) in &base.flags {
        let role = match role_str.as_str() {
            "primary" => FlagRole::Primary,
            _ => FlagRole::Secondary,
        };
        template.add(flag, role);
    }
    for (dim, value) in &base.amplifiers {
        *template.amplifiers.entry(dim.clone()).or_insert(0) = *value;
    }
    template
}
```

In `execute_risk_rules_with_sets`, change the first line and set `fixed_tier`:

```rust
    let mut template = build_base(rule_def.base.as_ref());
    if let Some(tier_str) = &rule_def.tier {
        template.fixed_tier = parse_tier(tier_str);
    }
```

- [ ] **Step 4: Run the tests — verify they pass**

Run: `cargo test -p permit0-dsl`
Expected: PASS (whole crate builds and tests green).

- [ ] **Step 5: Commit (A2 + A3 together)**

```bash
cargo fmt --all
git add crates/permit0-dsl/src/schema/risk_rule.rs crates/permit0-dsl/src/risk_executor.rs
git commit -m "feat(dsl): optional tier: field on risk rules, optional base"
```

---

## Task A4: Validate fixed-tier rules

**Files:**
- Modify: `crates/permit0-dsl/src/validate.rs`
- Test: same file

**Context:** First read `crates/permit0-dsl/src/validate.rs` to find where a single `RiskRuleDef` is validated (the function the pack loader calls per risk-rule file) and how it reports errors. Add the checks below into that path, matching the existing error type/return shape. The logic is fully specified here.

The five rules to enforce, given a `&RiskRuleDef` named `rule`:

1. If `rule.tier` is `Some(s)`: `s` must parse via `risk_executor::parse_tier` → else error `"invalid tier: {s}"`.
2. If `rule.tier` parses to `Tier::Critical` → error `"tier: critical is not allowed — use a gate: mutation to force CRITICAL"`.
3. If `rule.tier` is `Some` and `rule.base` has a non-empty `amplifiers` map → error `"amplifiers are ignored when tier: is set — remove them"`.
4. If `rule.tier` is `Some`, every mutation in every `rules`/`session_rules` branch must be `MutationDef::Gate` → else error `"fixed-tier rules may only use gate: mutations (no add_flag/upgrade/etc.)"`.
5. If `rule.tier` is `None` and `rule.base` is `None` → error `"a scored rule must declare a base: section"`.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `validate.rs` (adapt the assertion style to the file's actual validator entry point — call it `validate_risk_rule` below; rename to the real function):

```rust
    fn rule(yaml: &str) -> crate::schema::risk_rule::RiskRuleDef {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn fixed_tier_rule_is_valid() {
        let r = rule(r#"
permit0_pack: "p/x"
action_type: "email.delete"
tier: high
base: { flags: { MUTATION: primary } }
session_rules:
  - when: { record_count: { gt: 10 } }
    then: [ { gate: "bulk" } ]
"#);
        assert!(validate_risk_rule(&r).is_ok());
    }

    #[test]
    fn rejects_tier_critical() {
        let r = rule("permit0_pack: p/x\naction_type: a.b\ntier: critical\n");
        assert!(validate_risk_rule(&r).is_err());
    }

    #[test]
    fn rejects_amplifiers_with_fixed_tier() {
        let r = rule(r#"
permit0_pack: "p/x"
action_type: "a.b"
tier: high
base: { flags: { MUTATION: primary }, amplifiers: { scope: 10 } }
"#);
        assert!(validate_risk_rule(&r).is_err());
    }

    #[test]
    fn rejects_non_gate_mutation_with_fixed_tier() {
        let r = rule(r#"
permit0_pack: "p/x"
action_type: "a.b"
tier: high
rules:
  - when: { x: { gt: 1 } }
    then: [ { upgrade: { dim: scope, delta: 5 } } ]
"#);
        assert!(validate_risk_rule(&r).is_err());
    }

    #[test]
    fn rejects_scored_rule_without_base() {
        let r = rule("permit0_pack: p/x\naction_type: a.b\n");
        assert!(validate_risk_rule(&r).is_err());
    }
```

- [ ] **Step 2: Run the tests — verify they fail**

Run: `cargo test -p permit0-dsl -- validate::tests`
Expected: FAIL — checks not implemented.

- [ ] **Step 3: Implement the validation**

Add this function to `validate.rs` and call it from the existing per-risk-rule validation entry point (merge its errors into whatever the file returns):

```rust
use crate::schema::risk_rule::{MutationDef, RiskRuleDef};

/// Validate a risk rule's fixed-tier / scored-rule invariants.
/// Returns `Err(message)` on the first violation.
pub fn validate_risk_rule(rule: &RiskRuleDef) -> Result<(), String> {
    match &rule.tier {
        Some(tier_str) => {
            let tier = crate::risk_executor::parse_tier(tier_str)
                .ok_or_else(|| format!("invalid tier: {tier_str}"))?;
            if tier == permit0_types::Tier::Critical {
                return Err(
                    "tier: critical is not allowed — use a gate: mutation to force CRITICAL"
                        .to_string(),
                );
            }
            if let Some(base) = &rule.base {
                if !base.amplifiers.is_empty() {
                    return Err(
                        "amplifiers are ignored when tier: is set — remove them".to_string()
                    );
                }
            }
            let all_then = rule
                .rules
                .iter()
                .flat_map(|r| &r.then)
                .chain(rule.session_rules.iter().flat_map(|r| &r.then));
            for m in all_then {
                if !matches!(m, MutationDef::Gate { .. }) {
                    return Err(
                        "fixed-tier rules may only use gate: mutations \
                         (no add_flag/upgrade/etc.)"
                            .to_string(),
                    );
                }
            }
        }
        None => {
            if rule.base.is_none() {
                return Err("a scored rule must declare a base: section".to_string());
            }
        }
    }
    Ok(())
}
```

If the file's existing validator returns a `Vec` of violations rather than `Result`, push the message instead of returning. Keep the standalone `validate_risk_rule` returning `Result<(), String>` so the unit tests above compile; have the file-level validator call it and adapt.

- [ ] **Step 4: Run the tests — verify they pass**

Run: `cargo test -p permit0-dsl`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/permit0-dsl/src/validate.rs
git commit -m "feat(dsl): validate fixed-tier risk rules"
```

---

## Task A5: Rewrite `delete.yaml` and re-lock the email pack

**Files:**
- Modify: `packs/permit0/email/risk_rules/delete.yaml`
- Modify: `packs/permit0/email/pack.lock.yaml` (regenerated)

- [ ] **Step 1: Replace `delete.yaml` with the fixed-tier version**

Overwrite `packs/permit0/email/risk_rules/delete.yaml` with exactly:

```yaml
permit0_pack: "permit0/email"
action_type: "email.delete"
# Fixed tier: HIGH. Even a soft delete (Trash / Deleted Items) means the
# user can no longer find the message — an intrinsically human-review action.
# Scoring is bypassed; `base.flags` are kept only as audit/UI labels.
tier: high
base:
  flags:
    MUTATION: primary
    GOVERNANCE: secondary
session_rules:
  # Bulk delete is a known cover-up vector — escalate to CRITICAL (Deny).
  - when:
      record_count:
        gt: 10
    then:
      - gate: "bulk delete (>10 messages) — known cover-up vector"
```

- [ ] **Step 2: Regenerate the lockfile**

Run: `cargo run -- pack lock packs/permit0/email`
Expected: `Wrote .../pack.lock.yaml (NN files, ... bytes)`.

- [ ] **Step 3: Validate the pack**

Run: `cargo run -- pack validate packs/permit0/email`
Expected: no violations reported.

- [ ] **Step 4: Verify the verdict locally**

Run: `echo '{"tool_name":"gmail_delete","parameters":{"message_id":"plan-check"}}' | cargo run -- check`
Expected: `Permission: HUMANINTHELOOP` (or `HumanInTheLoop`), `Tier: HIGH`, `Source: Scorer`.

Run: `echo '{"tool_name":"outlook_delete","parameters":{"message_id":"plan-check-2"}}' | cargo run -- check`
Expected: same — `Tier: HIGH`.

- [ ] **Step 5: Commit**

```bash
git add packs/permit0/email/risk_rules/delete.yaml packs/permit0/email/pack.lock.yaml
git commit -m "feat(packs): email.delete uses fixed tier: high + bulk-delete gate"
```

---

## Task A6: Update the calibration corpus

**Files:**
- Modify: `corpora/calibration/008-gmail-delete-single.yaml`
- Modify: `corpora/calibration/021-outlook-delete-single.yaml`
- Create: `corpora/calibration/027-gmail-delete-bulk.yaml`

- [ ] **Step 1: Update `008-gmail-delete-single.yaml`**

Replace its contents with:

```yaml
# Soft-deleting a single message — intrinsically human-review (fixed tier).
name: gmail_delete_single
tool_name: gmail_delete
parameters:
  message_id: "18f2c9a1b7d4e2"
expected_tier: "High"
expected_permission: "HumanInTheLoop"
```

- [ ] **Step 2: Update `021-outlook-delete-single.yaml`**

Replace its contents with:

```yaml
# Soft-deleting a single message — intrinsically human-review (fixed tier).
name: outlook_delete_single
tool_name: outlook_delete
parameters:
  message_id: "AAMkAGI2zB"
expected_tier: "High"
expected_permission: "HumanInTheLoop"
```

- [ ] **Step 3: Create `027-gmail-delete-bulk.yaml`**

**Context:** First check how a bulk delete supplies `record_count` — grep an existing corpus file or pack normalizer for `record_count`. The `session_rule` reads `record_count` from session data. If the calibration harness has no way to inject session `record_count`, this case cannot be expressed as a static corpus fixture — in that case **skip this step** and instead add a Rust test in `crates/permit0-dsl/src/risk_executor.rs` asserting the bulk gate fires (the `fixed_tier_rule_sets_template_fixed_tier` test in A3 already covers this). If the harness supports it, create the file:

```yaml
# Bulk delete (>10 messages) — escalates to CRITICAL via gate.
name: gmail_delete_bulk
tool_name: gmail_delete
parameters:
  message_id: "18f2c9a1b7d4e2"
session:
  record_count: 50
expected_tier: "Critical"
expected_permission: "Deny"
```

- [ ] **Step 4: Run the calibration suite**

Run: `cargo run -- calibrate test`
Expected: all cases pass, including 008 and 021 with the new expectations.

- [ ] **Step 5: Commit**

```bash
git add corpora/calibration/008-gmail-delete-single.yaml corpora/calibration/021-outlook-delete-single.yaml
git add corpora/calibration/027-gmail-delete-bulk.yaml 2>/dev/null || true
git commit -m "test(calibration): delete-single → High/HITL, add bulk-delete case"
```

- [ ] **Step 6: Phase A gate — full check**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo nextest run --workspace`
Expected: clean. Fix any fallout before starting Phase B.

---

# Phase B — Policy-cache invalidation + TTL

**Design note (refines the spec):** with the spec's chosen "startup clear-if-changed" invalidation, the config fingerprint lives only in a `cache_meta` table, not on every `policy_cache` row. `policy_cache_get` filters by TTL only; the fingerprint comparison + `policy_cache_clear()` happens once at engine startup. Row shape: `(norm_hash, permission, risk_score_json, created_at)`.

## Task B1: `CachedDecision` type + `PolicyState` trait changes

**Files:**
- Modify: `crates/permit0-store/src/policy_state.rs`

- [ ] **Step 1: Add the `CachedDecision` type and change the trait**

In `policy_state.rs`, add `use permit0_types::RiskScore;` to the imports (keep `NormHash, Permission`), then add:

```rust
/// A cached policy decision plus the risk score that produced it.
#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub permission: Permission,
    /// The risk score that produced this verdict, if one was recorded.
    /// `None` for verdicts with no score (allowlist-style cached entries).
    pub risk_score: Option<RiskScore>,
}
```

Replace the four policy-cache trait methods with:

```rust
    // ── Policy cache ──

    /// Fetch a cached decision. Returns `None` if absent or older than
    /// `ttl_secs` (the impl compares against the current wall clock).
    async fn policy_cache_get(
        &self,
        hash: &NormHash,
        ttl_secs: i64,
    ) -> Result<Option<CachedDecision>, StateError>;

    /// Store a decision with the current timestamp.
    async fn policy_cache_set(
        &self,
        hash: NormHash,
        decision: Permission,
        risk_score: Option<RiskScore>,
    ) -> Result<(), StateError>;

    async fn policy_cache_clear(&self) -> Result<(), StateError>;
    async fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError>;

    // ── Cache metadata (config fingerprint for startup reconciliation) ──

    async fn cache_meta_get(&self, key: &str) -> Result<Option<String>, StateError>;
    async fn cache_meta_set(&self, key: &str, value: &str) -> Result<(), StateError>;
```

- [ ] **Step 2: Verify it does not compile yet (expected)**

Run: `cargo build -p permit0-store`
Expected: FAIL — the three impls no longer satisfy the trait. Fixed in B2–B4.

- [ ] **Step 3: Do NOT commit yet** — commit with B2–B4 (the crate must build).

---

## Task B2: SQLite `PolicyState` impl

**Files:**
- Modify: `crates/permit0-store/src/policy_state_sqlite.rs`

- [ ] **Step 1: Update the schema in `init_schema`**

Change the `policy_cache` table in the `execute_batch` string and add `cache_meta`:

```sql
            CREATE TABLE IF NOT EXISTS policy_cache (
                norm_hash BLOB PRIMARY KEY,
                permission TEXT NOT NULL,
                risk_score_json TEXT,
                created_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
```

After the `execute_batch(...)` call for the table DDL (still inside `init_schema`), add idempotent column migrations for pre-existing dev databases:

```rust
        // Back-fill columns on databases created before the cache v2 schema.
        // Errors (duplicate column) are expected and ignored.
        for stmt in [
            "ALTER TABLE policy_cache ADD COLUMN risk_score_json TEXT",
            "ALTER TABLE policy_cache ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
        ] {
            let _ = conn.execute_batch(stmt);
        }
```

- [ ] **Step 2: Add a timestamp helper and update imports**

Add near the top of the file:

```rust
use permit0_types::RiskScore;
use crate::policy_state::CachedDecision;

/// Current Unix time in whole seconds.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
```

(Adjust the existing `use crate::policy_state::{...}` line to include `CachedDecision`.)

- [ ] **Step 3: Replace `policy_cache_get` and `policy_cache_set`**

```rust
    async fn policy_cache_get(
        &self,
        hash: &NormHash,
        ttl_secs: i64,
    ) -> Result<Option<CachedDecision>, StateError> {
        let cutoff = now_epoch() - ttl_secs;
        let conn = self.conn.lock().map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT permission, risk_score_json FROM policy_cache
                 WHERE norm_hash = ?1 AND created_at > ?2",
            )
            .map_err(|e| StateError::Io(e.to_string()))?;
        let row: Option<(String, Option<String>)> = stmt
            .query_row(params![hash_to_blob(hash), cutoff], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .opt()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(|(perm, rsj)| CachedDecision {
            permission: str_to_permission(&perm),
            risk_score: rsj.and_then(|j| serde_json::from_str(&j).ok()),
        }))
    }

    async fn policy_cache_set(
        &self,
        hash: NormHash,
        p: Permission,
        risk_score: Option<RiskScore>,
    ) -> Result<(), StateError> {
        let rsj = risk_score
            .as_ref()
            .map(|s| serde_json::to_string(s))
            .transpose()
            .map_err(|e| StateError::Io(e.to_string()))?;
        let conn = self.conn.lock().map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO policy_cache
                (norm_hash, permission, risk_score_json, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![hash_to_blob(&hash), permission_to_str(p), rsj, now_epoch()],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }
```

(`policy_cache_clear` and `policy_cache_invalidate` are unchanged.)

- [ ] **Step 4: Add `cache_meta_get` / `cache_meta_set`**

Add these methods to the `impl PolicyState for SqlitePolicyState` block:

```rust
    async fn cache_meta_get(&self, key: &str) -> Result<Option<String>, StateError> {
        let conn = self.conn.lock().map_err(|e| StateError::Io(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached("SELECT value FROM cache_meta WHERE key = ?1")
            .map_err(|e| StateError::Io(e.to_string()))?;
        stmt.query_row(params![key], |row| row.get::<_, String>(0))
            .opt()
            .map_err(|e| StateError::Io(e.to_string()))
    }

    async fn cache_meta_set(&self, key: &str, value: &str) -> Result<(), StateError> {
        let conn = self.conn.lock().map_err(|e| StateError::Io(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }
```

- [ ] **Step 5: Fix the existing `policy_cache_clear` test**

In `mod tests`, replace the `policy_cache_clear` test body's `policy_cache_set` / `policy_cache_get` calls with the new signatures and add a TTL test:

```rust
    #[tokio::test]
    async fn policy_cache_clear() {
        let s = SqlitePolicyState::in_memory().unwrap();
        s.policy_cache_set(h(), Permission::Allow, None).await.unwrap();
        s.policy_cache_set(h2(), Permission::Deny, None).await.unwrap();
        s.policy_cache_clear().await.unwrap();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_none());
        assert!(s.policy_cache_get(&h2(), 3600).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn policy_cache_ttl_expires() {
        let s = SqlitePolicyState::in_memory().unwrap();
        s.policy_cache_set(h(), Permission::Allow, None).await.unwrap();
        // Fresh entry visible with a positive TTL.
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_some());
        // A TTL of -1 places the cutoff in the future → entry is expired.
        assert!(s.policy_cache_get(&h(), -1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cache_meta_round_trips() {
        let s = SqlitePolicyState::in_memory().unwrap();
        assert!(s.cache_meta_get("fp").await.unwrap().is_none());
        s.cache_meta_set("fp", "abc123").await.unwrap();
        assert_eq!(s.cache_meta_get("fp").await.unwrap().as_deref(), Some("abc123"));
    }
```

- [ ] **Step 6: Do NOT commit yet** — continue to B3, B4.

---

## Task B3: Postgres `PolicyState` impl

**Files:**
- Create: `crates/permit0-store/migrations/state/<next-number>_policy_cache_v2.sql`
- Modify: `crates/permit0-store/src/pg_state.rs`

- [ ] **Step 1: Create the migration**

List `crates/permit0-store/migrations/state/` to find the highest-numbered migration; create the next one (e.g. if the last is `0001_init.sql`, create `0002_policy_cache_v2.sql`) with:

```sql
ALTER TABLE policy_cache ADD COLUMN IF NOT EXISTS risk_score_json TEXT;
ALTER TABLE policy_cache ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS cache_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

- [ ] **Step 2: Update imports and add the timestamp helper**

In `pg_state.rs`, add:

```rust
use permit0_types::RiskScore;
use crate::policy_state::CachedDecision;

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
```

(Extend the existing `use crate::policy_state::{...}` line to include `CachedDecision`.)

- [ ] **Step 3: Replace `policy_cache_get` and `policy_cache_set`**

```rust
    async fn policy_cache_get(
        &self,
        hash: &NormHash,
        ttl_secs: i64,
    ) -> Result<Option<CachedDecision>, StateError> {
        let cutoff = now_epoch() - ttl_secs;
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT permission, risk_score_json FROM policy_cache
             WHERE norm_hash = $1 AND created_at > $2",
        )
        .bind(hash.as_slice())
        .bind(cutoff)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(|(perm, rsj)| CachedDecision {
            permission: str_to_permission(&perm),
            risk_score: rsj.and_then(|j| serde_json::from_str(&j).ok()),
        }))
    }

    async fn policy_cache_set(
        &self,
        hash: NormHash,
        p: Permission,
        risk_score: Option<RiskScore>,
    ) -> Result<(), StateError> {
        let rsj = risk_score
            .as_ref()
            .map(|s| serde_json::to_string(s))
            .transpose()
            .map_err(|e| StateError::Io(e.to_string()))?;
        sqlx::query(
            "INSERT INTO policy_cache (norm_hash, permission, risk_score_json, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (norm_hash) DO UPDATE SET
                permission = EXCLUDED.permission,
                risk_score_json = EXCLUDED.risk_score_json,
                created_at = EXCLUDED.created_at",
        )
        .bind(hash.as_slice())
        .bind(permission_to_str(p))
        .bind(rsj)
        .bind(now_epoch())
        .execute(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }
```

- [ ] **Step 4: Add `cache_meta_get` / `cache_meta_set`**

```rust
    async fn cache_meta_get(&self, key: &str) -> Result<Option<String>, StateError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM cache_meta WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(row.map(|(v,)| v))
    }

    async fn cache_meta_set(&self, key: &str, value: &str) -> Result<(), StateError> {
        sqlx::query(
            "INSERT INTO cache_meta (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(())
    }
```

- [ ] **Step 5: Do NOT commit yet** — continue to B4.

---

## Task B4: In-memory `PolicyState` impl

**Files:**
- Modify: `crates/permit0-store/src/policy_state_memory.rs`

- [ ] **Step 1: Update struct fields**

Change imports and the struct:

```rust
use permit0_types::{NormHash, Permission, RiskScore};
use crate::policy_state::{CachedDecision, HumanDecisionRow, PendingApprovalRow, PolicyState, StateError};
```

```rust
pub struct InMemoryPolicyState {
    denylist: RwLock<HashMap<NormHash, String>>,
    allowlist: RwLock<HashMap<NormHash, String>>,
    /// norm_hash → (permission, risk_score, created_at_epoch_secs)
    policy_cache: RwLock<HashMap<NormHash, (Permission, Option<RiskScore>, i64)>>,
    cache_meta: RwLock<HashMap<String, String>>,
    pending_approvals: RwLock<HashMap<String, PendingApprovalRow>>,
    resolved_approvals: RwLock<HashMap<String, HumanDecisionRow>>,
}
```

Update `new()` to initialise `cache_meta: RwLock::new(HashMap::new()),`.

- [ ] **Step 2: Add the timestamp helper**

```rust
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
```

- [ ] **Step 3: Replace the policy-cache methods and add cache-meta methods**

```rust
    async fn policy_cache_get(
        &self,
        hash: &NormHash,
        ttl_secs: i64,
    ) -> Result<Option<CachedDecision>, StateError> {
        let cutoff = now_epoch() - ttl_secs;
        let g = self.policy_cache.read().map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(hash).filter(|(_, _, ts)| *ts > cutoff).map(
            |(perm, rs, _)| CachedDecision {
                permission: *perm,
                risk_score: rs.clone(),
            },
        ))
    }

    async fn policy_cache_set(
        &self,
        hash: NormHash,
        p: Permission,
        risk_score: Option<RiskScore>,
    ) -> Result<(), StateError> {
        let mut g = self.policy_cache.write().map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, (p, risk_score, now_epoch()));
        Ok(())
    }

    async fn policy_cache_clear(&self) -> Result<(), StateError> {
        let mut g = self.policy_cache.write().map_err(|e| StateError::Io(e.to_string()))?;
        g.clear();
        Ok(())
    }

    async fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self.policy_cache.write().map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    async fn cache_meta_get(&self, key: &str) -> Result<Option<String>, StateError> {
        let g = self.cache_meta.read().map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(key).cloned())
    }

    async fn cache_meta_set(&self, key: &str, value: &str) -> Result<(), StateError> {
        let mut g = self.cache_meta.write().map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(key.to_string(), value.to_string());
        Ok(())
    }
```

- [ ] **Step 4: Fix the `policy_cache_crud` test**

Replace it with:

```rust
    #[tokio::test]
    async fn policy_cache_crud() {
        let s = InMemoryPolicyState::new();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_none());
        s.policy_cache_set(h(), Permission::Allow, None).await.unwrap();
        assert_eq!(
            s.policy_cache_get(&h(), 3600).await.unwrap().map(|c| c.permission),
            Some(Permission::Allow)
        );
        s.policy_cache_invalidate(&h()).await.unwrap();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_none());
    }
```

- [ ] **Step 5: Build the store crate and run its tests**

Run: `cargo nextest run -p permit0-store`
Expected: PASS — all three impls build and their cache tests are green.

- [ ] **Step 6: Commit (B1–B4 together)**

```bash
cargo fmt --all
git add crates/permit0-store/
git commit -m "feat(store): policy cache gains TTL, RiskScore storage, cache_meta"
```

---

## Task B5: Engine — thread TTL/fingerprint, return RiskScore on hit, reconcile

**Files:**
- Modify: `crates/permit0-engine/src/engine.rs`
- Modify: `crates/permit0-engine/src/learning/analyzer.rs` (call-site fix)
- Modify: `crates/permit0-scoring/src/constants.rs` (model version constant)

**Context:** Read `engine.rs` to find the `Engine` struct, its builder (`EngineBuilder`), and the call sites of `policy_cache_get` (step 4, ~line 207) and `policy_cache_set` (step 7, ~line 318).

- [ ] **Step 1: Add the scoring-model version constant**

In `crates/permit0-scoring/src/constants.rs`, add at the end (before `#[cfg(test)]`):

```rust
/// Version tag for the scoring model (weights, categories, thresholds).
/// BUMP THIS whenever any constant in this file changes — it feeds the
/// policy-cache config fingerprint so stale cached verdicts are dropped.
pub const SCORING_MODEL_VERSION: &str = "2026-05-22.1";
```

- [ ] **Step 2: Add fields to the `Engine` struct**

Add two fields to `Engine`:

```rust
    /// Policy-cache TTL in seconds (from PERMIT0_POLICY_CACHE_TTL_SECS).
    cache_ttl_secs: i64,
    /// Fingerprint of the scoring config + packs, for cache reconciliation.
    config_fingerprint: String,
```

In `EngineBuilder`, add matching optional fields and setters:

```rust
    // in EngineBuilder struct:
    cache_ttl_secs: Option<i64>,
    config_fingerprint: Option<String>,
```

```rust
    // EngineBuilder methods:
    pub fn cache_ttl_secs(mut self, secs: i64) -> Self {
        self.cache_ttl_secs = Some(secs);
        self
    }

    pub fn config_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.config_fingerprint = Some(fp.into());
        self
    }
```

In `EngineBuilder::build` (or wherever `Engine` is constructed), set:

```rust
            cache_ttl_secs: self.cache_ttl_secs.unwrap_or(3600),
            config_fingerprint: self.config_fingerprint.unwrap_or_default(),
```

- [ ] **Step 3: Update the step-4 cache read**

Replace the `if let Some(cached) = self.state.policy_cache_get(&norm_hash).await? { ... }` block with:

```rust
        // Step 4: Policy cache
        if let Some(cached) = self
            .state
            .policy_cache_get(&norm_hash, self.cache_ttl_secs)
            .await?
        {
            trace.push(stage(
                "policy_cache",
                "hit",
                &redacted,
                Some(serde_json::json!({ "cached_permission": cached.permission })),
            ));
            let result = PermissionResult {
                permission: cached.permission,
                norm_action: norm,
                risk_score: cached.risk_score,
                source: DecisionSource::PolicyCache,
            };
            self.log_decision(&result, tool_call, ctx, trace).await?;
            return Ok(result);
        }
```

- [ ] **Step 4: Update the step-7 cache write**

Replace the cache-write block with:

```rust
        // Cache only definitive verdicts (Allow / Deny). Caching HumanInTheLoop
        // would race with calibrate's overwrite (see note above).
        if permission != Permission::HumanInTheLoop {
            self.state
                .policy_cache_set(norm_hash, permission, Some(risk_score.clone()))
                .await?;
        }
```

- [ ] **Step 5: Add the reconcile method**

Add a public async method on `Engine`:

```rust
    /// Compare the live config fingerprint against the one the cache was
    /// last populated under; clear the policy cache on mismatch. Call once
    /// at daemon startup. A no-op when fingerprints match.
    pub async fn reconcile_policy_cache(&self) -> Result<(), EngineError> {
        const KEY: &str = "config_fingerprint";
        let stored = self.state.cache_meta_get(KEY).await?;
        if stored.as_deref() != Some(self.config_fingerprint.as_str()) {
            self.state.policy_cache_clear().await?;
            self.state
                .cache_meta_set(KEY, &self.config_fingerprint)
                .await?;
        }
        Ok(())
    }
```

(Use the crate's actual error type in the signature — match what `get_permission` returns. `StateError` converts into it already since `policy_cache_get` is used with `?`.)

- [ ] **Step 6: Fix the `learning/analyzer.rs` call site**

`analyzer.rs` calls `policy_cache_set(norm_hash, human_decision)`. Update it to the new 3-arg signature — the calibration overwrite has no risk score to attach:

```rust
        .policy_cache_set(norm_hash, human_decision, None)
```

Also update any `policy_cache_get` call in that file's tests to pass a TTL (`3600`) and read `.permission` off the `CachedDecision`.

- [ ] **Step 7: Build and test the engine crate**

Run: `cargo nextest run -p permit0-engine`
Expected: PASS. Fix any remaining call-site breakage (tests that call the cache methods).

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add crates/permit0-engine/ crates/permit0-scoring/src/constants.rs
git commit -m "feat(engine): policy cache TTL + RiskScore passthrough + reconcile"
```

---

## Task B6: Compute the fingerprint and wire reconcile into `serve`

**Files:**
- Modify: `crates/permit0-cli/src/engine_factory.rs`
- Modify: `crates/permit0-cli/src/cmd/serve.rs`

**Context:** Read `engine_factory.rs` (full) to see how `build_engine_from_packs` loads packs and the profile and constructs the engine via `EngineBuilder`. Read `cmd/serve.rs` to find where the engine is built for the daemon.

- [ ] **Step 1: Add a fingerprint function to `engine_factory.rs`**

`permit0-store`'s audit code already depends on `sha2`; if `sha2` is not a dependency of `permit0-cli`, add `sha2 = "0.10"` to `crates/permit0-cli/Cargo.toml` `[dependencies]`. Then add:

```rust
/// Fingerprint of everything that can change a verdict: the scoring model
/// version, the active profile, and every pack lockfile under `packs_dir`.
/// Feeds the policy-cache startup reconciliation.
fn compute_config_fingerprint(packs_dir: &std::path::Path, profile: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(permit0_scoring::constants::SCORING_MODEL_VERSION.as_bytes());
    hasher.update(b"\x00");
    hasher.update(profile.unwrap_or("<none>").as_bytes());
    hasher.update(b"\x00");
    // Every pack.lock.yaml, sorted for determinism.
    let mut locks: Vec<std::path::PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(packs_dir)
        .into_iter()
        .flatten()
    {
        if entry.file_name() == "pack.lock.yaml" {
            locks.push(entry.path().to_path_buf());
        }
    }
    locks.sort();
    for lock in locks {
        if let Ok(bytes) = std::fs::read(&lock) {
            hasher.update(&bytes);
        }
    }
    format!("{:x}", hasher.finalize())
}
```

If `walkdir` is not already a dependency of `permit0-cli`, either add it or replace the walk with `std::fs::read_dir` recursion. Check `Cargo.toml` first — the pack loader likely already uses `walkdir`.

- [ ] **Step 2: Pass TTL and fingerprint into the builder**

In `build_engine_from_packs` (and any sibling builder used by `serve`), after determining `packs_dir` and `profile`, compute and pass:

```rust
    let ttl_secs: i64 = std::env::var("PERMIT0_POLICY_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    let fingerprint = compute_config_fingerprint(packs_dir_path, profile);
```

Add `.cache_ttl_secs(ttl_secs).config_fingerprint(fingerprint)` to the `EngineBuilder` chain.

- [ ] **Step 3: Call `reconcile_policy_cache` at daemon startup**

In `cmd/serve.rs`, after the engine is built and before the HTTP server starts accepting requests, add:

```rust
    engine
        .reconcile_policy_cache()
        .await
        .context("reconciling policy cache against config fingerprint")?;
```

(Match the surrounding error handling — `serve.rs` uses `anyhow`, so `.context(...)` is available.)

- [ ] **Step 4: Build the workspace**

Run: `cargo build --workspace`
Expected: clean build.

- [ ] **Step 5: Manual smoke test**

```bash
# Fresh local check still works and delete is HIGH:
echo '{"tool_name":"gmail_delete","parameters":{"message_id":"smoke"}}' | cargo run -- check
```

Expected: `Tier: HIGH`, `Permission: HUMANINTHELOOP`.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/permit0-cli/
git commit -m "feat(cli): config fingerprint + policy-cache reconcile on serve startup"
```

---

## Task B7: Phase B gate — full verification

- [ ] **Step 1: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: clean.

- [ ] **Step 2: Full test suite**

Run: `cargo nextest run --workspace`
Expected: all green.

- [ ] **Step 3: Calibration**

Run: `cargo run -- calibrate test`
Expected: all cases pass.

- [ ] **Step 4: Commit any fmt fixes**

```bash
git status --short
# if anything changed:
git add -A && git commit -m "chore: fmt/clippy fixes"
```

---

## Task B8: Rollout (operational — not code)

These steps deploy the fix to the running Docker stack. They are **manual** and should be run by the operator (some need a human-confirmed destructive DB write).

- [ ] **Step 1:** Confirm the pack lockfile is current — `git status` shows `packs/permit0/email/pack.lock.yaml` committed (Task A5).
- [ ] **Step 2:** Rebuild the engine image — packs are baked in (`PERMIT0_PACKS_DIR=/etc/permit0/packs`):
  ```bash
  docker compose -f permit0-mcp/docker-compose.yml build   # or the engine's compose file
  docker compose ... up -d permit0-engine
  ```
- [ ] **Step 3:** One-time clear of pre-fingerprint cache rows (the reconcile only triggers on *changed* fingerprint; rows written before the schema change have `created_at = 0` and will TTL-expire on their own, but an explicit clear is immediate):
  ```bash
  docker exec permit0-state-db psql -U permit0 -d permit0_state -c "DELETE FROM policy_cache;"
  ```
- [ ] **Step 4:** Verify against the live daemon:
  ```bash
  curl -s -X POST http://127.0.0.1:9090/api/v1/check -H 'content-type: application/json' \
    -d '{"tool_name":"gmail_delete","parameters":{"message_id":"rollout-check"}}'
  ```
  Expected: `"permission":"human"`, `"tier":"HIGH"`, `"source":"Scorer"`.

---

## Self-review notes (completed by plan author)

- **Spec coverage:** §3 (fixed `tier:`) → A1–A5; §3.2 validation → A4; §4 (cache fingerprint/TTL/RiskScore) → B1–B6; §5 (testing) → A6, per-task tests, B7; §6 (rollout) → B8. The spec's per-row `config_fingerprint` column is intentionally replaced by a `cache_meta` row (documented in the Phase B design note) — equivalent under the chosen startup-clear strategy.
- **Type consistency:** `CachedDecision { permission, risk_score }`, `policy_cache_get(hash, ttl_secs) -> Option<CachedDecision>`, `policy_cache_set(hash, permission, Option<RiskScore>)`, `cache_meta_get/set` — used identically across B1–B5. `parse_tier` defined in A3, reused in A4. `SCORING_MODEL_VERSION` defined in B5, used in B6.
- **Known soft spots flagged inline:** the bulk-delete corpus case (A6 Step 3) depends on whether the calibration harness can inject session `record_count` — a fallback Rust test is specified. Validator entry-point name in A4 must be reconciled with the real `validate.rs` structure — the standalone `validate_risk_rule` is written to be callable regardless.
