#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use permit0_types::{Permission, Tier};

use permit0_store::PolicyState;
use permit0_store::audit::{AuditEntry, AuditFilter, AuditSink};

use super::override_store::OverrideStore;
use super::types::{ActionStats, LearningSuggestion, TrainingFeatures};

/// Thresholds for learning system decisions.
pub const ALLOWLIST_MIN_APPROVALS: u64 = 50;
pub const ALLOWLIST_MAX_OVERRIDE_RATE: f64 = 0.02;
pub const AUTO_APPROVE_MIN_APPROVALS: u64 = 100;
pub const AUTO_APPROVE_MAX_OVERRIDE_RATE: f64 = 0.05;
pub const ALWAYS_HUMAN_ROUTE_THRESHOLD: f64 = 0.80;

/// The learning analyzer: computes stats and generates suggestions.
///
/// Reads decision history from the audit sink (the chained source of
/// truth) and overrides from the dedicated override store.
pub struct LearningAnalyzer {
    audit_sink: Arc<dyn AuditSink>,
    override_store: Arc<dyn OverrideStore>,
}

impl LearningAnalyzer {
    pub fn new(audit_sink: Arc<dyn AuditSink>, override_store: Arc<dyn OverrideStore>) -> Self {
        Self {
            audit_sink,
            override_store,
        }
    }

    /// Compute statistics for a given action type.
    pub async fn action_stats(&self, action_type: &str) -> Result<ActionStats, String> {
        let entries = self
            .audit_sink
            .query(&AuditFilter {
                action_type: Some(action_type.into()),
                limit: Some(10_000),
                ..Default::default()
            })
            .await
            .map_err(|e| e.to_string())?;

        let total_decisions = entries.len() as u64;
        let human_approvals = entries
            .iter()
            .filter(|e| e.decision == Permission::Allow)
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
    pub async fn should_auto_approve(&self, action_type: &str) -> Result<bool, String> {
        let stats = self.action_stats(action_type).await?;
        Ok(stats.suggest_auto_approve)
    }

    /// Generate suggestions for all action types with enough data.
    pub async fn generate_suggestions(&self) -> Result<Vec<LearningSuggestion>, String> {
        let all_entries = self
            .audit_sink
            .query(&AuditFilter {
                limit: Some(10_000),
                ..Default::default()
            })
            .await
            .map_err(|e| e.to_string())?;

        let mut action_types: Vec<String> = all_entries
            .iter()
            .map(|e| e.norm_action.action_type.as_action_str())
            .collect();
        action_types.sort();
        action_types.dedup();

        let mut suggestions = Vec::new();
        for at in &action_types {
            let stats = self.action_stats(at).await?;

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

            if stats.total_decisions >= 10 {
                let human_decisions = all_entries
                    .iter()
                    .filter(|e| {
                        e.norm_action.action_type.as_action_str() == *at
                            && e.decision == Permission::HumanInTheLoop
                    })
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

    /// Extract training features from audit entries (for ML pipeline).
    pub async fn extract_training_features(
        &self,
        action_type: &str,
    ) -> Result<Vec<TrainingFeatures>, String> {
        let entries = self
            .audit_sink
            .query(&AuditFilter {
                action_type: Some(action_type.into()),
                limit: Some(10_000),
                ..Default::default()
            })
            .await
            .map_err(|e| e.to_string())?;

        let overrides = self.override_store.get_overrides_by_action(action_type)?;

        let override_hashes: std::collections::HashSet<permit0_types::NormHash> =
            overrides.iter().map(|o| o.norm_hash).collect();

        let mut features = Vec::new();
        for e in &entries {
            features.push(entry_to_features(e, &overrides, &override_hashes));
        }

        Ok(features)
    }
}

fn entry_to_features(
    e: &AuditEntry,
    overrides: &[super::types::HumanOverride],
    override_hashes: &std::collections::HashSet<permit0_types::NormHash>,
) -> TrainingFeatures {
    let was_overridden = override_hashes.contains(&e.norm_hash);
    let label = if was_overridden {
        overrides
            .iter()
            .find(|o| o.norm_hash == e.norm_hash)
            .map(|o| o.human_decision)
            .unwrap_or(e.decision)
    } else {
        e.decision
    };

    let flags = e
        .risk_score
        .as_ref()
        .map(|rs| rs.flags.clone())
        .unwrap_or_default();
    let flag_map: HashMap<String, bool> = flags.iter().map(|f| (f.clone(), true)).collect();

    let action_type_str = e.norm_action.action_type.as_action_str();
    let parts: Vec<&str> = action_type_str.splitn(2, '.').collect();
    let domain = parts.first().copied().unwrap_or("").to_string();
    let verb = parts.get(1).copied().unwrap_or("").to_string();

    let raw_score = e.risk_score.as_ref().map(|rs| rs.raw).unwrap_or(0.0);
    let tier = e
        .risk_score
        .as_ref()
        .map(|rs| rs.tier)
        .unwrap_or(Tier::Medium);
    let blocked = e.risk_score.as_ref().is_some_and(|rs| rs.blocked);

    TrainingFeatures {
        raw_score,
        score: (raw_score * 100.0) as u32,
        tier,
        flag_count: flags.len(),
        blocked,
        flags: flag_map,
        action_type: action_type_str,
        domain,
        verb,
        label,
        was_overridden,
    }
}

/// Record a human override and promote to policy cache.
///
/// Records the override in the override store, then updates the policy
/// cache so the next identical call is a cache hit.
pub async fn record_human_decision(
    state: &dyn PolicyState,
    override_store: &dyn OverrideStore,
    override_record: super::types::HumanOverride,
) -> Result<(), String> {
    let norm_hash = override_record.norm_hash;
    let human_decision = override_record.human_decision;

    override_store.record_override(override_record)?;

    state
        .policy_cache_set(norm_hash, human_decision)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::override_store::InMemoryOverrideStore;
    use super::*;
    use permit0_store::audit::chain::{GENESIS_HASH, compute_entry_hash};
    use permit0_store::audit::signer::{AuditSigner, Ed25519Signer};
    use permit0_store::{InMemoryAuditSink, InMemoryPolicyState};
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission, RiskScore, Tier};

    fn make_entry(
        action_type: &str,
        permission: Permission,
        idx: u32,
        signer: &Ed25519Signer,
        prev: &str,
    ) -> AuditEntry {
        let mut e = AuditEntry {
            entry_id: format!("e-{idx}"),
            timestamp: format!("2025-01-{:02}T00:00:00Z", (idx % 28) + 1),
            sequence: (idx as u64) + 1,
            decision: permission,
            decision_source: "scorer".into(),
            norm_action: NormAction {
                action_type: ActionType::parse(action_type).unwrap(),
                channel: "test".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "test".into(),
                    surface_command: "test cmd".into(),
                },
            },
            norm_hash: [idx as u8; 32],
            raw_tool_call: serde_json::json!({}),
            risk_score: Some(RiskScore {
                raw: 0.45,
                score: 45,
                tier: Tier::Medium,
                blocked: false,
                flags: vec!["FINANCIAL".into()],
                block_reason: None,
                reason: "test".into(),
            }),
            scoring_detail: None,
            agent_id: String::new(),
            session_id: None,
            task_goal: None,
            org_id: String::new(),
            environment: String::new(),
            engine_version: "0.1".into(),
            pack_id: String::new(),
            pack_version: String::new(),
            dsl_version: "1.0".into(),
            human_review: None,
            engine_decision: None,
            token_id: None,
            prev_hash: prev.into(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: None,
            retroactive_decision: None,
            decision_trace: Vec::new(),
        };
        e.entry_hash = compute_entry_hash(&e);
        e.signature = signer.sign(&e.entry_hash);
        e
    }

    async fn setup(
        action_type: &str,
        allow_count: u32,
        human_count: u32,
    ) -> (Arc<InMemoryAuditSink>, Arc<InMemoryOverrideStore>) {
        let sink = Arc::new(InMemoryAuditSink::new());
        let overrides = Arc::new(InMemoryOverrideStore::new());
        let signer = Ed25519Signer::generate();
        let mut prev = GENESIS_HASH.to_string();
        let mut idx = 0u32;
        for _ in 0..allow_count {
            let e = make_entry(action_type, Permission::Allow, idx, &signer, &prev);
            prev = e.entry_hash.clone();
            sink.append(&e).await.unwrap();
            idx += 1;
        }
        for _ in 0..human_count {
            let e = make_entry(action_type, Permission::HumanInTheLoop, idx, &signer, &prev);
            prev = e.entry_hash.clone();
            sink.append(&e).await.unwrap();
            idx += 1;
        }
        (sink, overrides)
    }

    #[tokio::test]
    async fn cache_promotion_on_human_approve() {
        let state = Arc::new(InMemoryPolicyState::new());
        let override_store = Arc::new(InMemoryOverrideStore::new());
        let norm_hash = [42u8; 32];

        assert!(state.policy_cache_get(&norm_hash).await.unwrap().is_none());

        let override_record = super::super::types::HumanOverride {
            original_decision: Permission::HumanInTheLoop,
            human_decision: Permission::Allow,
            norm_hash,
            action_type: "email.send".into(),
            reason: "Safe pattern".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reviewer: "alice@example.com".into(),
        };
        record_human_decision(&*state, &*override_store, override_record)
            .await
            .unwrap();

        assert_eq!(
            state.policy_cache_get(&norm_hash).await.unwrap(),
            Some(Permission::Allow)
        );
    }

    #[tokio::test]
    async fn allowlist_suggestion_fires_at_threshold() {
        let (sink, overrides) = setup("email.send", 50, 0).await;
        let analyzer = LearningAnalyzer::new(sink, overrides);
        let stats = analyzer.action_stats("email.send").await.unwrap();
        assert!(stats.suggest_allowlist);
        assert_eq!(stats.human_approvals, 50);
        assert_eq!(stats.override_rate, 0.0);
    }

    #[tokio::test]
    async fn allowlist_suggestion_does_not_fire_below_threshold() {
        let (sink, overrides) = setup("email.send", 49, 0).await;
        let analyzer = LearningAnalyzer::new(sink, overrides);
        let stats = analyzer.action_stats("email.send").await.unwrap();
        assert!(!stats.suggest_allowlist);
    }

    #[tokio::test]
    async fn allowlist_suggestion_blocked_by_override_rate() {
        let (sink, overrides) = setup("email.send", 50, 0).await;
        for i in 0..2u32 {
            overrides
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
        let analyzer = LearningAnalyzer::new(sink, overrides);
        let stats = analyzer.action_stats("email.send").await.unwrap();
        assert!(!stats.suggest_allowlist);
    }

    #[tokio::test]
    async fn auto_approve_requires_100_examples() {
        let (sink, overrides) = setup("email.send", 99, 0).await;
        let analyzer = LearningAnalyzer::new(sink, overrides);
        assert!(!analyzer.should_auto_approve("email.send").await.unwrap());

        let (sink2, overrides2) = setup("email.send", 100, 0).await;
        let analyzer2 = LearningAnalyzer::new(sink2, overrides2);
        assert!(analyzer2.should_auto_approve("email.send").await.unwrap());
    }

    #[tokio::test]
    async fn training_features_extraction() {
        let (sink, overrides) = setup("email.send", 5, 0).await;
        let analyzer = LearningAnalyzer::new(sink, overrides);
        let features = analyzer
            .extract_training_features("email.send")
            .await
            .unwrap();
        assert_eq!(features.len(), 5);
        assert_eq!(features[0].action_type, "email.send");
        assert_eq!(features[0].domain, "email");
        assert_eq!(features[0].verb, "send");
        assert!(!features[0].was_overridden);
    }

    #[tokio::test]
    async fn training_features_with_override() {
        let (sink, overrides) = setup("email.send", 3, 0).await;
        overrides
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

        let analyzer = LearningAnalyzer::new(sink, overrides);
        let features = analyzer
            .extract_training_features("email.send")
            .await
            .unwrap();

        let overridden: Vec<&TrainingFeatures> =
            features.iter().filter(|f| f.was_overridden).collect();
        assert_eq!(overridden.len(), 1);
        assert_eq!(overridden[0].label, Permission::Allow);
    }

    #[tokio::test]
    async fn generate_suggestions_promotes_allowlist() {
        let (sink, overrides) = setup("email.send", 55, 0).await;
        let analyzer = LearningAnalyzer::new(sink, overrides);
        let suggestions = analyzer.generate_suggestions().await.unwrap();
        let allowlist_suggestions: Vec<&LearningSuggestion> = suggestions
            .iter()
            .filter(|s| matches!(s, LearningSuggestion::PromoteToAllowlist { .. }))
            .collect();
        assert_eq!(allowlist_suggestions.len(), 1);
    }

    #[tokio::test]
    async fn always_human_suggestion_when_high_human_rate() {
        // Use a real action_type (the parser only accepts known domains).
        let (sink, overrides) = setup("email.send", 1, 9).await;
        let analyzer = LearningAnalyzer::new(sink, overrides);
        let suggestions = analyzer.generate_suggestions().await.unwrap();
        let always_human: Vec<&LearningSuggestion> = suggestions
            .iter()
            .filter(|s| matches!(s, LearningSuggestion::AddToAlwaysHuman { .. }))
            .collect();
        assert_eq!(always_human.len(), 1);
    }
}
