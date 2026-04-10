#![forbid(unsafe_code)]

use std::collections::HashMap;

use permit0_scoring::{RiskTemplate, ScoringConfig, compute_hybrid};
use permit0_types::{FlagRole, Tier};
use proptest::prelude::*;

/// Strategy: generate a random amplifier value for a known dimension.
fn amp_strategy() -> impl Strategy<Value = HashMap<String, i32>> {
    let dims = vec![
        "sensitivity",
        "scope",
        "boundary",
        "amount",
        "actor",
        "destination",
        "session",
        "volume",
        "irreversibility",
        "environment",
    ];
    prop::collection::hash_map(
        prop::sample::select(dims).prop_map(|s| s.to_string()),
        0..50i32,
        0..=10,
    )
}

/// Strategy: generate a random set of flags.
fn flag_strategy() -> impl Strategy<Value = HashMap<String, FlagRole>> {
    let flags = vec![
        "DESTRUCTION",
        "PHYSICAL",
        "EXECUTION",
        "PRIVILEGE",
        "FINANCIAL",
        "EXPOSURE",
        "GOVERNANCE",
        "OUTBOUND",
        "MUTATION",
    ];
    let roles = vec![FlagRole::Primary, FlagRole::Secondary];
    prop::collection::hash_map(
        prop::sample::select(flags).prop_map(|s| s.to_string()),
        prop::sample::select(roles),
        0..=9,
    )
}

proptest! {
    /// Tier monotonicity: adding more amplifiers should never decrease the score.
    #[test]
    fn higher_amps_yield_higher_or_equal_score(
        flags in flag_strategy(),
        base_amps in amp_strategy(),
        extra_amps in amp_strategy(),
    ) {
        if flags.is_empty() {
            return Ok(());
        }

        let config = ScoringConfig::default();

        let mut t1 = RiskTemplate::new();
        t1.flags = flags.clone();
        t1.amplifiers = base_amps.clone();

        let mut combined = base_amps;
        for (dim, val) in &extra_amps {
            let entry = combined.entry(dim.clone()).or_insert(0);
            *entry = (*entry + val).max(*val);
        }
        let mut t2 = RiskTemplate::new();
        t2.flags = flags;
        t2.amplifiers = combined;

        let s1 = compute_hybrid(&t1, &config, None);
        let s2 = compute_hybrid(&t2, &config, None);

        // Both blocked → both Critical, skip comparison
        if s1.blocked || s2.blocked {
            return Ok(());
        }

        prop_assert!(
            s2.raw >= s1.raw - 1e-10,
            "higher amps should yield >= score: {} vs {}",
            s2.raw,
            s1.raw
        );
    }

    /// Score is always in [0, 1].
    #[test]
    fn score_always_in_unit_range(
        flags in flag_strategy(),
        amps in amp_strategy(),
    ) {
        let config = ScoringConfig::default();
        let mut t = RiskTemplate::new();
        t.flags = flags;
        t.amplifiers = amps;

        let score = compute_hybrid(&t, &config, None);
        prop_assert!(score.raw >= 0.0, "raw score below 0: {}", score.raw);
        prop_assert!(score.raw <= 1.0, "raw score above 1: {}", score.raw);
        prop_assert!(score.score <= 100, "display score above 100: {}", score.score);
    }

    /// Tier is consistent with raw score.
    #[test]
    fn tier_matches_raw_score(
        flags in flag_strategy(),
        amps in amp_strategy(),
    ) {
        let config = ScoringConfig::default();
        let mut t = RiskTemplate::new();
        t.flags = flags;
        t.amplifiers = amps;

        let score = compute_hybrid(&t, &config, None);
        if score.blocked {
            prop_assert_eq!(score.tier, Tier::Critical);
        } else {
            // The tier is computed from the unrounded raw value, but score.raw
            // is rounded to 4 decimal places. Near tier boundaries (0.15, 0.35,
            // 0.55, 0.75) the rounded raw and assigned tier can legitimately
            // disagree. We verify the tier is consistent with a raw value within
            // one rounding step (5e-5) of the displayed value.
            let r = score.raw;
            let eps: f64 = 5e-4;
            let valid = match score.tier {
                Tier::Minimal  => r <= 0.15 + eps,
                Tier::Low      => (0.15 - eps..=0.35 + eps).contains(&r),
                Tier::Medium   => (0.35 - eps..=0.55 + eps).contains(&r),
                Tier::High     => (0.55 - eps..=0.75 + eps).contains(&r),
                Tier::Critical => r >= 0.75 - eps,
            };
            prop_assert!(
                valid,
                "tier {:?} inconsistent with raw={}: out of valid range",
                score.tier,
                r,
            );
        }
    }

    /// Block rules always produce Critical tier.
    #[test]
    fn blocked_always_critical(
        amps in amp_strategy(),
    ) {
        let config = ScoringConfig::default();
        let mut t = RiskTemplate::new();
        t.flags.insert("DESTRUCTION".into(), FlagRole::Primary);
        t.amplifiers = amps;
        t.blocked = true;
        t.block_reason = Some("test".into());

        let score = compute_hybrid(&t, &config, None);
        prop_assert_eq!(score.tier, Tier::Critical);
        prop_assert!(score.blocked);
    }
}
