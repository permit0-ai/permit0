#![forbid(unsafe_code)]

use std::collections::HashSet;

use permit0_types::Tier;

use crate::context::SessionContext;

/// Derive the session amplifier dimension (0–30) from session history.
///
/// Higher values indicate a riskier session context. Used as the `session`
/// amplifier dimension in hybrid scoring.
pub fn session_amplifier_score(session: &SessionContext) -> i32 {
    if session.records.is_empty() {
        return 5; // baseline
    }

    let high_count = session
        .records
        .iter()
        .filter(|r| r.tier >= Tier::High)
        .count();
    let medium_count = session
        .records
        .iter()
        .filter(|r| r.tier == Tier::Medium)
        .count();
    let distinct_flags: HashSet<&str> = session
        .records
        .iter()
        .flat_map(|r| r.flags.iter().map(|f| f.as_str()))
        .collect();

    let score = high_count as i32 * 8 + medium_count as i32 * 3 + distinct_flags.len() as i32;
    score.min(30)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ActionRecord;

    fn make_record(tier: Tier, flags: &[&str]) -> ActionRecord {
        ActionRecord {
            action_type: "test".into(),
            tier,
            flags: flags.iter().map(|f| f.to_string()).collect(),
            timestamp: 1_700_000_000.0,
            entities: serde_json::Map::new(),
        }
    }

    #[test]
    fn empty_session_baseline() {
        let ctx = SessionContext::new("test");
        assert_eq!(session_amplifier_score(&ctx), 5);
    }

    #[test]
    fn high_tier_contributes_8() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record(Tier::High, &[]));
        assert_eq!(session_amplifier_score(&ctx), 8);
    }

    #[test]
    fn medium_tier_contributes_3() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record(Tier::Medium, &[]));
        assert_eq!(session_amplifier_score(&ctx), 3);
    }

    #[test]
    fn flags_contribute_1_each() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record(Tier::Low, &["EXPOSURE", "MUTATION"]));
        assert_eq!(session_amplifier_score(&ctx), 2);
    }

    #[test]
    fn capped_at_30() {
        let mut ctx = SessionContext::new("test");
        for _ in 0..10 {
            ctx.push(make_record(Tier::High, &["a", "b", "c"]));
        }
        assert_eq!(session_amplifier_score(&ctx), 30);
    }

    #[test]
    fn monotonicity_with_records() {
        let mut ctx = SessionContext::new("test");
        // Start with a Low-tier record so we're past the empty-session baseline
        ctx.push(make_record(Tier::Low, &["flag_a"]));
        let mut prev_score = session_amplifier_score(&ctx);
        // Adding higher-tier actions should never decrease the score
        for tier in [Tier::Medium, Tier::High, Tier::Critical] {
            ctx.push(make_record(tier, &["flag_b"]));
            let score = session_amplifier_score(&ctx);
            assert!(
                score >= prev_score,
                "score decreased: {prev_score} -> {score}"
            );
            prev_score = score;
        }
    }

    #[test]
    fn duplicate_flags_not_double_counted() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record(Tier::Low, &["EXPOSURE"]));
        ctx.push(make_record(Tier::Low, &["EXPOSURE"]));
        // Two Low (0 each) + 1 distinct flag = 1
        assert_eq!(session_amplifier_score(&ctx), 1);
    }
}
