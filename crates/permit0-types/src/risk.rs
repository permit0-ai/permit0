#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Risk tier — five bands mapping raw score to policy routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    Minimal = 0,  // raw < 0.15 → Allow
    Low = 1,      // raw < 0.35 → Allow
    Medium = 2,   // raw < 0.55 → Agent reviewer → Human | Deny
    High = 3,     // raw < 0.75 → Human-in-the-loop
    Critical = 4, // raw >= 0.75 → Deny
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => write!(f, "MINIMAL"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Tier thresholds — ceiling values. Score <= ceiling → tier.
pub const TIER_THRESHOLDS: &[(f64, Tier)] = &[
    (0.15, Tier::Minimal),
    (0.35, Tier::Low),
    (0.55, Tier::Medium),
    (0.75, Tier::High),
    (1.00, Tier::Critical),
];

/// Flag role within a risk template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlagRole {
    Primary,
    Secondary,
}

/// Output of the risk scoring pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Raw score 0.0–1.0 — use for math and composition.
    pub raw: f64,
    /// Display score 0–100.
    pub score: u32,
    /// Tier band.
    pub tier: Tier,
    /// Which risk flags fired.
    pub flags: Vec<String>,
    /// Human-readable explanation of scoring.
    pub reason: String,
    /// Whether a gate or block rule fired.
    pub blocked: bool,
    /// Reason for block, if any.
    pub block_reason: Option<String>,
}

/// Construct a `RiskScore` from a raw value and metadata.
pub fn to_risk_score(
    raw: f64,
    flags: Vec<String>,
    reason: &str,
    blocked: bool,
    block_reason: Option<String>,
) -> RiskScore {
    let raw = raw.clamp(0.0, 1.0);
    let score = (raw * 100.0).round() as u32;
    let tier = if blocked {
        Tier::Critical
    } else {
        TIER_THRESHOLDS
            .iter()
            .find(|(ceiling, _)| raw <= *ceiling)
            .map(|(_, t)| *t)
            .unwrap_or(Tier::Critical)
    };
    RiskScore {
        raw: (raw * 10000.0).round() / 10000.0,
        score,
        tier,
        flags,
        reason: reason.to_string(),
        blocked,
        block_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering() {
        assert!(Tier::Minimal < Tier::Low);
        assert!(Tier::Low < Tier::Medium);
        assert!(Tier::Medium < Tier::High);
        assert!(Tier::High < Tier::Critical);
    }

    #[test]
    fn to_risk_score_minimal() {
        let s = to_risk_score(0.10, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::Minimal);
        assert_eq!(s.score, 10);
        assert!(!s.blocked);
    }

    #[test]
    fn to_risk_score_boundaries() {
        // Exactly at boundary
        let s = to_risk_score(0.15, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::Minimal);

        let s = to_risk_score(0.16, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::Low);

        let s = to_risk_score(0.55, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::Medium);

        let s = to_risk_score(0.56, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::High);

        let s = to_risk_score(0.75, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::High);

        let s = to_risk_score(0.76, vec![], "test", false, None);
        assert_eq!(s.tier, Tier::Critical);
    }

    #[test]
    fn blocked_always_critical() {
        let s = to_risk_score(0.05, vec![], "blocked", true, Some("gate".into()));
        assert_eq!(s.tier, Tier::Critical);
        assert!(s.blocked);
    }

    #[test]
    fn raw_is_clamped() {
        let s = to_risk_score(1.5, vec![], "test", false, None);
        assert!((s.raw - 1.0).abs() < f64::EPSILON);

        let s = to_risk_score(-0.5, vec![], "test", false, None);
        assert!((s.raw).abs() < f64::EPSILON);
    }
}
