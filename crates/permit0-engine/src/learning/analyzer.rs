#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use permit0_types::{DecisionFilter, Permission};

use permit0_store::Store;

use super::override_store::OverrideStore;
use super::types::{ActionStats, LearningSuggestion, TrainingFeatures};

/// Thresholds for learning system decisions.
pub const ALLOWLIST_MIN_APPROVALS: u64 = 50;
pub const ALLOWLIST_MAX_OVERRIDE_RATE: f64 = 0.02;
pub const AUTO_APPROVE_MIN_APPROVALS: u64 = 100;
pub const AUTO_APPROVE_MAX_OVERRIDE_RATE: f64 = 0.05;
pub const ALWAYS_HUMAN_ROUTE_THRESHOLD: f64 = 0.80;

/// The learning analyzer: computes stats and generates suggestions.
pub struct LearningAnalyzer {
    store: Arc<dyn Store>,
    override_store: Arc<dyn OverrideStore>,
}

impl LearningAnalyzer {
    pub fn new(store: Arc<dyn Store>, override_store: Arc<dyn OverrideStore>) -> Self {
        Self {
            store,
            override_store,
        }
    }

    /// Compute statistics for a given action type.
    pub fn action_stats(&self, action_type: &str) -> Result<ActionStats, String> {
        let decisions = self
            .store
            .query_decisions(&DecisionFilter {
                action_type: Some(action_type.into()),
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;

        let total_decisions = decisions.len() as u64;
        let human_approvals = decisions
            .iter()
            .filter(|d| d.permission == Permission::Allow)
            .count() as u64;
        let overrides = self.override_store.count_overrides(action_type)?;

        let override_rate = if total_decisions > 0 {
            overrides as f64 / total_decisions as f64
        } else {
            0.0
        };

        let suggest_allowlist = human_approvals >= ALLOWLIST_MIN_APPROVALS
            && override_rate < ALLOWLIST_MAX_OVERRIDE_RATE;

        let suggest_auto_approve = human_approvals >= AUTO_APPROVE_MIN_APPROVALS
            && override_rate < AUTO_APPROVE_MAX_OVERRIDE_RATE;

        Ok(ActionStats {
            total_decisions,
            human_approvals,
            overrides,
            override_rate,
            suggest_allowlist,
            suggest_auto_approve,
        })
    }

    /// Check whether an action type should be auto-approved.
    ///
    /// Requires:
    /// - At least 100 human-approved examples
    /// - Override rate < 5%
    /// - No recent incidents (not yet tracked — placeholder for now)
    pub fn should_auto_approve(&self, action_type: &str) -> Result<bool, String> {
        let stats = self.action_stats(action_type)?;
        Ok(stats.suggest_auto_approve)
    }

    /// Generate suggestions for all action types with enough data.
    pub fn generate_suggestions(&self) -> Result<Vec<LearningSuggestion>, String> {
        // Get all distinct action types from recent decisions
        let all_decisions = self
            .store
            .query_decisions(&DecisionFilter {
                limit: Some(10_000),
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;

        let mut action_types: Vec<String> = all_decisions
            .iter()
            .map(|d| d.action_type.clone())
            .collect();
        action_types.sort();
        action_types.dedup();

        let mut suggestions = Vec::new();
        for at in &action_types {
            let stats = self.action_stats(at)?;

            if stats.suggest_allowlist {
                suggestions.push(LearningSuggestion::PromoteToAllowlist {
                    action_type: at.clone(),
                    approvals: stats.human_approvals,
                    override_rate_pct: (stats.override_rate * 100.0) as u64,
                });
            }

            if stats.suggest_auto_approve {
                suggestions.push(LearningSuggestion::EnableAutoApprove {
                    action_type: at.clone(),
                    approvals: stats.human_approvals,
                    override_rate_pct: (stats.override_rate * 100.0) as u64,
                });
            }

            // Check if reviewer routes to human > 80%
            if stats.total_decisions >= 10 {
                let human_decisions = all_decisions
                    .iter()
                    .filter(|d| d.action_type == *at && d.permission == Permission::HumanInTheLoop)
                    .count() as f64;
                let rate = human_decisions / stats.total_decisions as f64;
                if rate > ALWAYS_HUMAN_ROUTE_THRESHOLD {
                    suggestions.push(LearningSuggestion::AddToAlwaysHuman {
                        action_type: at.clone(),
                        human_route_rate_pct: (rate * 100.0) as u64,
                    });
                }
            }
        }

        Ok(suggestions)
    }

    /// Extract training features from decision records (for ML pipeline).
    pub fn extract_training_features(
        &self,
        action_type: &str,
    ) -> Result<Vec<TrainingFeatures>, String> {
        let decisions = self
            .store
            .query_decisions(&DecisionFilter {
                action_type: Some(action_type.into()),
                limit: Some(10_000),
                ..Default::default()
            })
            .map_err(|e| e.to_string())?;

        let overrides = self.override_store.get_overrides_by_action(action_type)?;

        let override_hashes: std::collections::HashSet<permit0_types::NormHash> =
            overrides.iter().map(|o| o.norm_hash).collect();

        let mut features = Vec::new();
        for d in &decisions {
            let was_overridden = override_hashes.contains(&d.norm_hash);
            let label = if was_overridden {
                // Find the human decision
                overrides
                    .iter()
                    .find(|o| o.norm_hash == d.norm_hash)
                    .map(|o| o.human_decision)
                    .unwrap_or(d.permission)
            } else {
                d.permission
            };

            let flag_map: HashMap<String, bool> =
                d.flags.iter().map(|f| (f.clone(), true)).collect();

            // Parse domain.verb from action_type
            let parts: Vec<&str> = d.action_type.splitn(2, '.').collect();
            let domain = parts.first().copied().unwrap_or("").to_string();
            let verb = parts.get(1).copied().unwrap_or("").to_string();

            features.push(TrainingFeatures {
                raw_score: d.risk_raw.unwrap_or(0.0),
                score: d.risk_raw.map(|r| (r * 100.0) as u32).unwrap_or(0),
                tier: d.tier.unwrap_or(permit0_types::Tier::Medium),
                flag_count: d.flags.len(),
                blocked: d.blocked,
                flags: flag_map,
                action_type: d.action_type.clone(),
                domain,
                verb,
                label,
                was_overridden,
            });
        }

        Ok(features)
    }
}

/// Record a human override and promote to policy cache.
///
/// This is the main entry point for capturing a human decision:
/// 1. Record the override in the override store
/// 2. Update the policy cache so the next identical call is a cache hit
pub fn record_human_decision(
    store: &dyn Store,
    override_store: &dyn OverrideStore,
    override_record: super::types::HumanOverride,
) -> Result<(), String> {
    let norm_hash = override_record.norm_hash;
    let human_decision = override_record.human_decision;

    // Record the override
    override_store.record_override(override_record)?;

    // Promote to policy cache
    store
        .policy_cache_set(norm_hash, human_decision)
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::override_store::InMemoryOverrideStore;
    use super::*;
    use permit0_store::InMemoryStore;
    use permit0_types::{DecisionRecord, Permission, Tier};

    fn make_decision(action_type: &str, permission: Permission, idx: u32) -> DecisionRecord {
        DecisionRecord {
            id: format!("test-{idx}"),
            norm_hash: [idx as u8; 32],
            action_type: action_type.into(),
            channel: "test".into(),
            permission,
            source: "scorer".into(),
            tier: Some(Tier::Medium),
            risk_raw: Some(0.45),
            blocked: false,
            flags: vec!["FINANCIAL".into()],
            timestamp: format!("2025-01-{:02}T00:00:00Z", (idx % 28) + 1),
            surface_tool: "test".into(),
            surface_command: "test cmd".into(),
            engine_permission: None,
            reviewer: None,
            reason: None,
        }
    }

    fn setup_store_with_decisions(
        action_type: &str,
        allow_count: u32,
        human_count: u32,
    ) -> (Arc<InMemoryStore>, Arc<InMemoryOverrideStore>) {
        let store = Arc::new(InMemoryStore::new());
        let override_store = Arc::new(InMemoryOverrideStore::new());
        let mut idx = 0u32;

        for _ in 0..allow_count {
            store
                .save_decision(make_decision(action_type, Permission::Allow, idx))
                .unwrap();
            idx += 1;
        }
        for _ in 0..human_count {
            store
                .save_decision(make_decision(action_type, Permission::HumanInTheLoop, idx))
                .unwrap();
            idx += 1;
        }

        (store, override_store)
    }

    #[test]
    fn cache_promotion_on_human_approve() {
        let store = Arc::new(InMemoryStore::new());
        let override_store = Arc::new(InMemoryOverrideStore::new());
        let norm_hash = [42u8; 32];

        // No cached decision initially
        assert!(store.policy_cache_get(&norm_hash).unwrap().is_none());

        // Human approves
        let override_record = super::super::types::HumanOverride {
            original_decision: Permission::HumanInTheLoop,
            human_decision: Permission::Allow,
            norm_hash,
            action_type: "email.send".into(),
            reason: "Safe pattern".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reviewer: "alice@example.com".into(),
        };
        record_human_decision(&*store, &*override_store, override_record).unwrap();

        // Now cached
        assert_eq!(
            store.policy_cache_get(&norm_hash).unwrap(),
            Some(Permission::Allow)
        );
    }

    #[test]
    fn allowlist_suggestion_fires_at_threshold() {
        let (store, override_store) = setup_store_with_decisions("email.send", 50, 0);

        let analyzer = LearningAnalyzer::new(store, override_store);
        let stats = analyzer.action_stats("email.send").unwrap();
        assert!(stats.suggest_allowlist);
        assert_eq!(stats.human_approvals, 50);
        assert_eq!(stats.override_rate, 0.0);
    }

    #[test]
    fn allowlist_suggestion_does_not_fire_below_threshold() {
        let (store, override_store) = setup_store_with_decisions("email.send", 49, 0);

        let analyzer = LearningAnalyzer::new(store, override_store);
        let stats = analyzer.action_stats("email.send").unwrap();
        assert!(!stats.suggest_allowlist);
    }

    #[test]
    fn allowlist_suggestion_blocked_by_override_rate() {
        let (store, override_store) = setup_store_with_decisions("email.send", 50, 0);

        // Record 2 overrides (2/50 = 4% > 2%)
        for i in 0..2u32 {
            override_store
                .record_override(super::super::types::HumanOverride {
                    original_decision: Permission::HumanInTheLoop,
                    human_decision: Permission::Allow,
                    norm_hash: [i as u8; 32],
                    action_type: "email.send".into(),
                    reason: "Override".into(),
                    timestamp: "2025-01-01T00:00:00Z".into(),
                    reviewer: "bob@example.com".into(),
                })
                .unwrap();
        }

        let analyzer = LearningAnalyzer::new(store, override_store);
        let stats = analyzer.action_stats("email.send").unwrap();
        assert!(!stats.suggest_allowlist); // 4% override rate > 2% threshold
    }

    #[test]
    fn auto_approve_requires_100_examples() {
        let (store, override_store) = setup_store_with_decisions("email.send", 99, 0);

        let analyzer = LearningAnalyzer::new(store, override_store);
        assert!(!analyzer.should_auto_approve("email.send").unwrap());

        let (store2, override_store2) = setup_store_with_decisions("email.send", 100, 0);

        let analyzer2 = LearningAnalyzer::new(store2, override_store2);
        assert!(analyzer2.should_auto_approve("email.send").unwrap());
    }

    #[test]
    fn training_features_extraction() {
        let (store, override_store) = setup_store_with_decisions("email.send", 5, 0);

        let analyzer = LearningAnalyzer::new(store, override_store);
        let features = analyzer.extract_training_features("email.send").unwrap();
        assert_eq!(features.len(), 5);
        assert_eq!(features[0].action_type, "email.send");
        assert_eq!(features[0].domain, "email");
        assert_eq!(features[0].verb, "send");
        assert!(!features[0].was_overridden);
    }

    #[test]
    fn training_features_with_override() {
        let (store, override_store) = setup_store_with_decisions("email.send", 3, 0);

        // Override the first decision
        override_store
            .record_override(super::super::types::HumanOverride {
                original_decision: Permission::HumanInTheLoop,
                human_decision: Permission::Allow,
                norm_hash: [0u8; 32],
                action_type: "email.send".into(),
                reason: "Safe".into(),
                timestamp: "2025-01-01T00:00:00Z".into(),
                reviewer: "alice@example.com".into(),
            })
            .unwrap();

        let analyzer = LearningAnalyzer::new(store, override_store);
        let features = analyzer.extract_training_features("email.send").unwrap();

        let overridden: Vec<&TrainingFeatures> =
            features.iter().filter(|f| f.was_overridden).collect();
        assert_eq!(overridden.len(), 1);
        assert_eq!(overridden[0].label, Permission::Allow);
    }

    #[test]
    fn generate_suggestions_promotes_allowlist() {
        let (store, override_store) = setup_store_with_decisions("email.send", 55, 0);

        let analyzer = LearningAnalyzer::new(store, override_store);
        let suggestions = analyzer.generate_suggestions().unwrap();

        let allowlist_suggestions: Vec<&LearningSuggestion> = suggestions
            .iter()
            .filter(|s| matches!(s, LearningSuggestion::PromoteToAllowlist { .. }))
            .collect();
        assert_eq!(allowlist_suggestions.len(), 1);
    }

    #[test]
    fn always_human_suggestion_when_high_human_rate() {
        let (store, override_store) = setup_store_with_decisions("risky.action", 1, 9);

        let analyzer = LearningAnalyzer::new(store, override_store);
        let suggestions = analyzer.generate_suggestions().unwrap();

        let always_human: Vec<&LearningSuggestion> = suggestions
            .iter()
            .filter(|s| matches!(s, LearningSuggestion::AddToAlwaysHuman { .. }))
            .collect();
        assert_eq!(always_human.len(), 1);
    }
}
