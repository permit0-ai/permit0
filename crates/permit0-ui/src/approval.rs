#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use permit0_types::{NormAction, Permission, RiskScore};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// A pending approval waiting for a human decision.
pub struct PendingApproval {
    /// Unique approval ID.
    pub approval_id: String,
    /// The normalized action under review.
    pub norm_action: NormAction,
    /// The risk score.
    pub risk_score: RiskScore,
    /// ISO 8601 timestamp when the approval was created.
    pub created_at: String,
    /// Sender to deliver the human decision back to the waiting engine.
    sender: Option<oneshot::Sender<HumanDecision>>,
}

/// The human's decision on a pending approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanDecision {
    /// The decision.
    pub permission: Permission,
    /// Reason for the decision.
    pub reason: String,
    /// Reviewer identity.
    pub reviewer: String,
}

/// Summary of a pending approval for the API response.
///
/// Surfaces the complete `NormAction` that permit0 was asked to score —
/// not just the parameter payload — so the human reviewer can audit
/// everything the engine saw: the `domain.verb` taxonomy classification,
/// the upstream MCP tool name + raw command, and the norm_hash they
/// would deny/allow-list against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApprovalSummary {
    pub approval_id: String,
    /// `domain.verb` e.g. `email.delete` (canonical taxonomy form).
    pub action_type: String,
    /// Domain alone, split from `action_type` (e.g. `email`).
    pub domain: String,
    /// Verb alone, split from `action_type` (e.g. `delete`).
    pub verb: String,
    pub source: String,
    /// The original MCP tool the agent invoked, before normalization
    /// (e.g. `gmail_delete`). Useful when a single `domain.verb` can be
    /// reached through several different tool surfaces.
    pub surface_tool: String,
    /// Audit-friendly stringification of the original tool call.
    pub surface_command: String,
    /// 32-byte hex norm_hash. Operators can copy this into the
    /// denylist/allowlist forms to make the verdict stick.
    pub norm_hash: String,
    pub risk_score: u32,
    pub tier: String,
    pub created_at: String,
    /// The normalized parameters (to, subject, body, message_id, …) the agent
    /// passed in. Lets the human reviewer audit the actual content before
    /// approving / denying.
    pub parameters: serde_json::Map<String, serde_json::Value>,
    /// Risk flags that fired during scoring (e.g. ["OUTBOUND", "MUTATION",
    /// "EXPOSURE", "GOVERNANCE"]). Helps the reviewer understand WHY this
    /// reached the current tier.
    pub flags: Vec<String>,
}

/// Default timeout for pending approvals (5 minutes).
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

/// Manages pending approvals.
pub struct ApprovalManager {
    pending: Mutex<HashMap<String, PendingApproval>>,
    timeout: Duration,
}

impl ApprovalManager {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            timeout: DEFAULT_APPROVAL_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Create a pending approval. Returns (approval_id, receiver).
    ///
    /// The caller should await the receiver with a timeout.
    pub fn create_pending(
        &self,
        norm_action: NormAction,
        risk_score: RiskScore,
    ) -> (String, oneshot::Receiver<HumanDecision>) {
        let approval_id = ulid::Ulid::new().to_string();
        let (tx, rx) = oneshot::channel();

        let pending = PendingApproval {
            approval_id: approval_id.clone(),
            norm_action,
            risk_score,
            created_at: chrono::Utc::now().to_rfc3339(),
            sender: Some(tx),
        };

        self.pending
            .lock()
            .unwrap()
            .insert(approval_id.clone(), pending);

        (approval_id, rx)
    }

    /// Submit a human decision for a pending approval.
    ///
    /// Returns true if the decision was delivered, false if expired/not found.
    pub fn submit_decision(&self, approval_id: &str, decision: HumanDecision) -> bool {
        let mut guard = self.pending.lock().unwrap();
        if let Some(mut pending) = guard.remove(approval_id) {
            if let Some(sender) = pending.sender.take() {
                return sender.send(decision).is_ok();
            }
        }
        false
    }

    /// List all pending approvals.
    pub fn list_pending(&self) -> Vec<PendingApprovalSummary> {
        let guard = self.pending.lock().unwrap();
        guard
            .values()
            .map(|p| {
                let action_type_str = p.norm_action.action_type.as_action_str();
                let (domain, verb) = match action_type_str.split_once('.') {
                    Some((d, v)) => (d.to_string(), v.to_string()),
                    None => (action_type_str.clone(), String::new()),
                };
                PendingApprovalSummary {
                    approval_id: p.approval_id.clone(),
                    action_type: action_type_str,
                    domain,
                    verb,
                    source: p.norm_action.source.clone(),
                    surface_tool: p.norm_action.execution.surface_tool.clone(),
                    surface_command: p.norm_action.execution.surface_command.clone(),
                    norm_hash: hex::encode(p.norm_action.norm_hash()),
                    risk_score: p.risk_score.score,
                    tier: p.risk_score.tier.to_string(),
                    created_at: p.created_at.clone(),
                    parameters: p.norm_action.parameters.clone(),
                    flags: p.risk_score.flags.clone(),
                }
            })
            .collect()
    }

    /// Get the configured timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Remove expired approvals (called periodically or on access).
    pub fn cleanup_expired(&self) {
        let mut guard = self.pending.lock().unwrap();
        let now = chrono::Utc::now();
        let timeout_secs = self.timeout.as_secs() as i64;

        guard.retain(|_, p| {
            if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&p.created_at) {
                let elapsed = now.signed_duration_since(created).num_seconds();
                elapsed < timeout_secs
            } else {
                false
            }
        });
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_types::{ActionType, ExecutionMeta, NormAction, RiskScore, Tier};

    fn make_norm_action() -> NormAction {
        NormAction {
            action_type: ActionType::parse("email.send").unwrap(),
            source: "gmail".into(),
            parameters: serde_json::Map::new(),
            execution: ExecutionMeta {
                surface_tool: "test".into(),
                surface_command: "test cmd".into(),
            },
        }
    }

    fn make_risk_score() -> RiskScore {
        RiskScore {
            raw: 0.45,
            score: 45,
            tier: Tier::Medium,
            blocked: false,
            flags: vec!["FINANCIAL".into()],
            block_reason: None,
            reason: "test".into(),
        }
    }

    #[tokio::test]
    async fn create_and_resolve_approval() {
        let manager = ApprovalManager::new();
        let (id, rx) = manager.create_pending(make_norm_action(), make_risk_score());

        // Submit decision
        let decision = HumanDecision {
            permission: Permission::Allow,
            reason: "Approved".into(),
            reviewer: "alice@example.com".into(),
        };
        assert!(manager.submit_decision(&id, decision));

        // Receiver gets the decision
        let received = rx.await.unwrap();
        assert_eq!(received.permission, Permission::Allow);
    }

    #[tokio::test]
    async fn submit_to_nonexistent_approval() {
        let manager = ApprovalManager::new();
        let decision = HumanDecision {
            permission: Permission::Allow,
            reason: "test".into(),
            reviewer: "test".into(),
        };
        assert!(!manager.submit_decision("nonexistent", decision));
    }

    #[test]
    fn list_pending_approvals() {
        let manager = ApprovalManager::new();
        let (_id1, _rx1) = manager.create_pending(make_norm_action(), make_risk_score());
        let (_id2, _rx2) = manager.create_pending(make_norm_action(), make_risk_score());

        let pending = manager.list_pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].action_type, "email.send");
    }

    #[tokio::test]
    async fn timeout_drops_sender() {
        let manager =
            ApprovalManager::with_timeout(ApprovalManager::new(), Duration::from_millis(1));
        let (_id, rx) = manager.create_pending(make_norm_action(), make_risk_score());

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(10)).await;
        manager.cleanup_expired();

        // Receiver should get an error (sender dropped)
        assert!(rx.await.is_err());
    }
}
