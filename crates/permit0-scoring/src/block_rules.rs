#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A block rule that, if matched, forces a CRITICAL/Deny result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRule {
    pub name: String,
    pub required_flags: Vec<String>,
    pub amp_thresholds: Vec<(String, f64)>,
    pub reason: String,
}

impl BlockRule {
    /// Check if this block rule fires given active flags and normalised amplifiers.
    pub fn matches(&self, active_flags: &[String], norm_amps: &HashMap<String, f64>) -> bool {
        let all_flags = self
            .required_flags
            .iter()
            .all(|f| active_flags.iter().any(|af| af == f));
        if !all_flags {
            return false;
        }
        self.amp_thresholds.iter().all(|(dim, threshold)| {
            norm_amps
                .get(dim.as_str())
                .copied()
                .unwrap_or(0.0)
                >= *threshold
        })
    }
}

/// The five immutable block rules that cannot be removed or weakened by any layer.
pub fn immutable_block_rules() -> Vec<BlockRule> {
    vec![
        BlockRule {
            name: "irreversible_destruction".into(),
            required_flags: vec!["DESTRUCTION".into()],
            amp_thresholds: vec![("irreversibility".into(), 0.90)],
            reason: "Irreversible destruction exceeds tolerable threshold".into(),
        },
        BlockRule {
            name: "financial_exfiltration".into(),
            required_flags: vec!["FINANCIAL".into(), "OUTBOUND".into()],
            amp_thresholds: vec![("amount".into(), 0.83), ("destination".into(), 0.75)],
            reason: "High-value outbound financial movement to untrusted destination".into(),
        },
        BlockRule {
            name: "privileged_prod_execution".into(),
            required_flags: vec!["EXECUTION".into(), "PRIVILEGE".into()],
            amp_thresholds: vec![("environment".into(), 0.80), ("scope".into(), 0.80)],
            reason: "Arbitrary execution with elevated privilege in production scope".into(),
        },
        BlockRule {
            name: "governance_trust_boundary".into(),
            required_flags: vec!["GOVERNANCE".into()],
            amp_thresholds: vec![("boundary".into(), 0.90)],
            reason: "Rule-change crossing a high trust boundary".into(),
        },
        BlockRule {
            name: "classified_external_send".into(),
            required_flags: vec!["OUTBOUND".into(), "EXPOSURE".into()],
            amp_thresholds: vec![("sensitivity".into(), 0.94), ("destination".into(), 0.75)],
            reason: "Highly sensitive data sent to untrusted external destination".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irreversible_destruction_fires() {
        let rules = immutable_block_rules();
        let rule = &rules[0];
        let flags = vec!["DESTRUCTION".into()];
        let mut amps = HashMap::new();
        amps.insert("irreversibility".into(), 0.95);
        assert!(rule.matches(&flags, &amps));
    }

    #[test]
    fn irreversible_destruction_below_threshold() {
        let rules = immutable_block_rules();
        let rule = &rules[0];
        let flags = vec!["DESTRUCTION".into()];
        let mut amps = HashMap::new();
        amps.insert("irreversibility".into(), 0.80);
        assert!(!rule.matches(&flags, &amps));
    }

    #[test]
    fn financial_exfiltration_missing_flag() {
        let rules = immutable_block_rules();
        let rule = &rules[1];
        let flags = vec!["FINANCIAL".into()]; // missing OUTBOUND
        let mut amps = HashMap::new();
        amps.insert("amount".into(), 0.90);
        amps.insert("destination".into(), 0.80);
        assert!(!rule.matches(&flags, &amps));
    }

    #[test]
    fn all_immutable_rules_have_unique_names() {
        let rules = immutable_block_rules();
        let names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        for (i, name) in names.iter().enumerate() {
            assert!(
                !names[i + 1..].contains(name),
                "duplicate block rule name: {name}"
            );
        }
    }
}
