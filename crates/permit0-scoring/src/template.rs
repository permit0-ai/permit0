#![forbid(unsafe_code)]

use std::collections::HashMap;

use permit0_types::FlagRole;
use serde::{Deserialize, Serialize};

use crate::constants::AMP_MAXES;

/// The mutable intermediate representation that risk rules build up before scoring.
/// Constructed from YAML `base` definitions and modified by YAML `rules`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTemplate {
    /// flag → primary | secondary
    pub flags: HashMap<String, FlagRole>,
    /// dimension → raw integer value
    pub amplifiers: HashMap<String, i32>,
    /// Whether a hard block has been triggered.
    pub blocked: bool,
    /// Reason for the block, if any.
    pub block_reason: Option<String>,
    /// Independent child assessments (splits).
    pub children: Vec<RiskTemplate>,
}

impl Default for RiskTemplate {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskTemplate {
    pub fn new() -> Self {
        Self {
            flags: HashMap::new(),
            amplifiers: HashMap::new(),
            blocked: false,
            block_reason: None,
            children: Vec::new(),
        }
    }

    // ── Mutation API ────────────────────────────────────────────────
    // The ONLY way to modify a template. Mapped 1:1 from YAML rule actions.

    /// Add flag if not present.
    pub fn add(&mut self, flag: &str, role: FlagRole) {
        self.flags.entry(flag.to_string()).or_insert(role);
    }

    /// Remove flag entirely.
    pub fn remove(&mut self, flag: &str) {
        self.flags.remove(flag);
    }

    /// Promote secondary → primary. No-op if already primary or absent.
    pub fn promote(&mut self, flag: &str) {
        if let Some(role) = self.flags.get_mut(flag) {
            *role = FlagRole::Primary;
        }
    }

    /// Demote primary → secondary. No-op if already secondary or absent.
    pub fn demote(&mut self, flag: &str) {
        if let Some(role) = self.flags.get_mut(flag) {
            *role = FlagRole::Secondary;
        }
    }

    /// Increase amplifier, capped at AMP_MAXES ceiling.
    pub fn upgrade(&mut self, dim: &str, delta: i32) {
        let max = amp_max(dim);
        let entry = self.amplifiers.entry(dim.to_string()).or_insert(0);
        *entry = (*entry + delta).min(max);
    }

    /// Decrease amplifier, floored at 0.
    pub fn downgrade(&mut self, dim: &str, delta: i32) {
        let entry = self.amplifiers.entry(dim.to_string()).or_insert(0);
        *entry = (*entry - delta).max(0);
    }

    /// Set exact value, clamped to [0, max].
    pub fn override_amp(&mut self, dim: &str, value: i32) {
        let max = amp_max(dim);
        self.amplifiers.insert(dim.to_string(), value.clamp(0, max));
    }

    /// Hard block — sets blocked and records reason.
    pub fn gate(&mut self, reason: &str) {
        self.blocked = true;
        self.block_reason = Some(reason.to_string());
    }

    /// Fork an independent child template for split scoring.
    pub fn split(&mut self, child: RiskTemplate) {
        self.children.push(child);
    }
}

/// Look up the max for a dimension, defaulting to 100 for unknown dims.
fn amp_max(dim: &str) -> i32 {
    AMP_MAXES
        .iter()
        .find(|(d, _)| *d == dim)
        .map(|(_, m)| *m)
        .unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_flag() {
        let mut t = RiskTemplate::new();
        t.add("FINANCIAL", FlagRole::Primary);
        assert_eq!(t.flags.get("FINANCIAL"), Some(&FlagRole::Primary));
    }

    #[test]
    fn add_does_not_overwrite() {
        let mut t = RiskTemplate::new();
        t.add("FINANCIAL", FlagRole::Primary);
        t.add("FINANCIAL", FlagRole::Secondary);
        assert_eq!(
            t.flags.get("FINANCIAL"),
            Some(&FlagRole::Primary),
            "add should not overwrite existing flag"
        );
    }

    #[test]
    fn promote_and_demote() {
        let mut t = RiskTemplate::new();
        t.add("OUTBOUND", FlagRole::Secondary);
        t.promote("OUTBOUND");
        assert_eq!(t.flags.get("OUTBOUND"), Some(&FlagRole::Primary));
        t.demote("OUTBOUND");
        assert_eq!(t.flags.get("OUTBOUND"), Some(&FlagRole::Secondary));
    }

    #[test]
    fn upgrade_caps_at_max() {
        let mut t = RiskTemplate::new();
        // amount max is 30
        t.upgrade("amount", 50);
        assert_eq!(t.amplifiers["amount"], 30);
    }

    #[test]
    fn downgrade_floors_at_zero() {
        let mut t = RiskTemplate::new();
        t.upgrade("amount", 10);
        t.downgrade("amount", 20);
        assert_eq!(t.amplifiers["amount"], 0);
    }

    #[test]
    fn override_amp_clamps() {
        let mut t = RiskTemplate::new();
        t.override_amp("amount", 999);
        assert_eq!(t.amplifiers["amount"], 30);
        t.override_amp("amount", -5);
        assert_eq!(t.amplifiers["amount"], 0);
    }

    #[test]
    fn gate_blocks() {
        let mut t = RiskTemplate::new();
        t.gate("test block");
        assert!(t.blocked);
        assert_eq!(t.block_reason.as_deref(), Some("test block"));
    }

    #[test]
    fn split_adds_child() {
        let mut t = RiskTemplate::new();
        let child = RiskTemplate::new();
        t.split(child);
        assert_eq!(t.children.len(), 1);
    }
}
