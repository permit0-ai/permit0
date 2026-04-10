#![forbid(unsafe_code)]

use std::collections::HashMap;

use permit0_types::{ActionType, RiskScore, to_risk_score};

use crate::config::ScoringConfig;
use crate::constants::{AMP_MAXES, MULTIPLICATIVE_DIMS};
use crate::template::RiskTemplate;

/// Normalise raw integer amplifiers to 0.0–1.0 using AMP_MAXES ceilings.
pub fn normalise_amps(amplifiers: &HashMap<String, i32>) -> HashMap<String, f64> {
    AMP_MAXES
        .iter()
        .map(|(dim, max)| {
            let raw = amplifiers.get(*dim).copied().unwrap_or(0);
            (dim.to_string(), (raw as f64 / *max as f64).clamp(0.0, 1.0))
        })
        .collect()
}

/// 6-step hybrid scorer.
///
/// 1. Template gate — if `t.blocked`, return CRITICAL immediately.
/// 2. Block rules — check all configured block rules against normalised amps.
/// 3. Category-weighted base — weighted sum of flag base weights × category amps.
/// 4. Multiplicative compound — product of (1 + weight × norm) for high-stakes dims.
/// 5. Additive boost — sum of weight × norm for remaining dims.
/// 6. Tanh squeeze — `tanh(intermediate × k)` → \[0, 1).
///
/// Splits are resolved last: `score = max(self, all children)`.
pub fn compute_hybrid(
    t: &RiskTemplate,
    config: &ScoringConfig,
    action_type: Option<&ActionType>,
) -> RiskScore {
    let active_flags: Vec<String> = t.flags.keys().cloned().collect();
    let norm = normalise_amps(&t.amplifiers);

    // Step 1 — template-level gate
    if t.blocked {
        return to_risk_score(
            1.0,
            active_flags,
            t.block_reason
                .as_deref()
                .unwrap_or("blocked by template gate"),
            true,
            t.block_reason.clone(),
        );
    }

    // Step 2 — block rules (base + profile + org additions)
    for rule in &config.block_rules {
        if rule.matches(&active_flags, &norm) {
            return to_risk_score(
                1.0,
                active_flags,
                &rule.reason,
                true,
                Some(rule.reason.clone()),
            );
        }
    }

    // Step 3 — category-weighted base
    let base: f64 = config
        .categories
        .iter()
        .map(|cat| {
            let flag_base: f64 = active_flags
                .iter()
                .filter(|f| cat.flags.contains(&f.as_str()))
                .map(|f| config.risk_weight(f))
                .sum();
            if flag_base == 0.0 {
                return 0.0;
            }
            let cat_amps: Vec<(&str, f64)> = cat
                .amps
                .iter()
                .map(|d| (*d, config.amp_weight(d)))
                .collect();
            let cat_sum: f64 = cat_amps.iter().map(|(_, w)| w).sum();
            if cat_sum == 0.0 {
                return 0.0;
            }
            let amp: f64 = cat_amps
                .iter()
                .map(|(d, w)| (w / cat_sum) * norm.get(*d).copied().unwrap_or(0.0))
                .sum();
            cat.weight * flag_base * (1.0 + amp) / 2.0
        })
        .sum();

    // Step 4 — multiplicative compound for high-stakes dims
    let compound: f64 = MULTIPLICATIVE_DIMS
        .iter()
        .map(|dim| 1.0 + config.amp_weight(dim) * norm.get(*dim).copied().unwrap_or(0.0))
        .product();

    // Step 5 — additive boost from remaining dims
    let add_boost: f64 = config
        .amp_weights
        .iter()
        .filter(|(d, _)| !MULTIPLICATIVE_DIMS.contains(&d.as_str()))
        .map(|(d, w)| w * norm.get(d.as_str()).copied().unwrap_or(0.0))
        .sum();

    let intermediate = base * compound * (1.0 + add_boost);

    // Step 6 — tanh squeeze
    let raw = (intermediate * config.tanh_k).tanh();

    let reason = format!(
        "flags={active_flags:?}, base={base:.4}, compound={compound:.4}, boost={add_boost:.4}"
    );
    let mut score = to_risk_score(raw, active_flags, &reason, false, None);

    // Apply per-action-type floor if configured
    if let Some(at) = action_type {
        if let Some(floor_tier) = config.action_type_floor(at) {
            if score.tier < floor_tier {
                score.tier = floor_tier;
            }
        }
    }

    // Resolve splits: final score = max(self, all children)
    for child in &t.children {
        let child_score = compute_hybrid(child, config, action_type);
        if child_score.raw > score.raw {
            score = child_score;
        }
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_types::Tier;

    #[test]
    fn normalise_amps_known_dim() {
        let mut amps = HashMap::new();
        amps.insert("amount".into(), 15); // max is 30
        let norm = normalise_amps(&amps);
        assert!((norm["amount"] - 0.5).abs() < 1e-10);
    }

    #[test]
    fn normalise_amps_clamps_above_max() {
        let mut amps = HashMap::new();
        amps.insert("environment".into(), 999); // max is 15
        let norm = normalise_amps(&amps);
        assert!((norm["environment"] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn normalise_amps_missing_returns_zero() {
        let amps = HashMap::new();
        let norm = normalise_amps(&amps);
        assert!((norm["amount"] - 0.0).abs() < 1e-10);
    }

    #[test]
    fn empty_template_scores_minimal() {
        let t = RiskTemplate::new();
        let config = ScoringConfig::default();
        let score = compute_hybrid(&t, &config, None);
        assert_eq!(score.tier, Tier::Minimal);
        assert!(!score.blocked);
    }

    #[test]
    fn blocked_template_returns_critical() {
        let mut t = RiskTemplate::new();
        t.gate("test gate");
        let config = ScoringConfig::default();
        let score = compute_hybrid(&t, &config, None);
        assert_eq!(score.tier, Tier::Critical);
        assert!(score.blocked);
    }

    #[test]
    fn block_rule_fires() {
        let mut t = RiskTemplate::new();
        t.add("DESTRUCTION", permit0_types::FlagRole::Primary);
        t.override_amp("irreversibility", 20); // max 20 → normalised 1.0
        let config = ScoringConfig::default();
        let score = compute_hybrid(&t, &config, None);
        assert!(score.blocked, "irreversible_destruction rule should fire");
        assert_eq!(score.tier, Tier::Critical);
    }

    #[test]
    fn split_takes_max() {
        let mut parent = RiskTemplate::new();
        parent.add("MUTATION", permit0_types::FlagRole::Primary);

        let mut child = RiskTemplate::new();
        child.add("DESTRUCTION", permit0_types::FlagRole::Primary);
        child.add("FINANCIAL", permit0_types::FlagRole::Primary);
        child.override_amp("amount", 25);
        child.override_amp("irreversibility", 10);
        child.override_amp("boundary", 10);

        parent.split(child);

        let config = ScoringConfig::default();
        let score = compute_hybrid(&parent, &config, None);
        // Child has more flags and amps, so should dominate
        assert!(score.raw > 0.0);
    }

    #[test]
    fn more_flags_higher_score() {
        let config = ScoringConfig::default();

        let mut t1 = RiskTemplate::new();
        t1.add("MUTATION", permit0_types::FlagRole::Primary);

        let mut t2 = RiskTemplate::new();
        t2.add("MUTATION", permit0_types::FlagRole::Primary);
        t2.add("DESTRUCTION", permit0_types::FlagRole::Primary);
        t2.add("FINANCIAL", permit0_types::FlagRole::Primary);

        let s1 = compute_hybrid(&t1, &config, None);
        let s2 = compute_hybrid(&t2, &config, None);
        assert!(s2.raw >= s1.raw, "more flags should yield higher or equal score");
    }
}
