#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use super::types::{BootstrapProposal, ProposalStatus};

/// Storage for bootstrap proposals.
pub trait ProposalStore: Send + Sync {
    /// Save a new proposal.
    fn save_proposal(&self, proposal: BootstrapProposal) -> Result<(), String>;

    /// Get a proposal by ID.
    fn get_proposal(&self, proposal_id: &str) -> Result<Option<BootstrapProposal>, String>;

    /// Get the pending proposal for an action type (if any).
    fn get_pending_for_action(
        &self,
        action_type: &str,
    ) -> Result<Option<BootstrapProposal>, String>;

    /// Update proposal status.
    fn update_status(
        &self,
        proposal_id: &str,
        status: ProposalStatus,
        reviewer: Option<String>,
        notes: Option<String>,
    ) -> Result<(), String>;

    /// List all proposals with a given status.
    fn list_by_status(&self, status: ProposalStatus) -> Result<Vec<BootstrapProposal>, String>;
}

/// In-memory proposal store for testing.
pub struct InMemoryProposalStore {
    proposals: RwLock<HashMap<String, BootstrapProposal>>,
}

impl InMemoryProposalStore {
    pub fn new() -> Self {
        Self {
            proposals: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryProposalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProposalStore for InMemoryProposalStore {
    fn save_proposal(&self, proposal: BootstrapProposal) -> Result<(), String> {
        let mut guard = self.proposals.write().map_err(|e| e.to_string())?;
        guard.insert(proposal.proposal_id.clone(), proposal);
        Ok(())
    }

    fn get_proposal(&self, proposal_id: &str) -> Result<Option<BootstrapProposal>, String> {
        let guard = self.proposals.read().map_err(|e| e.to_string())?;
        Ok(guard.get(proposal_id).cloned())
    }

    fn get_pending_for_action(
        &self,
        action_type: &str,
    ) -> Result<Option<BootstrapProposal>, String> {
        let guard = self.proposals.read().map_err(|e| e.to_string())?;
        Ok(guard
            .values()
            .find(|p| p.action_type == action_type && p.status == ProposalStatus::Pending)
            .cloned())
    }

    fn update_status(
        &self,
        proposal_id: &str,
        status: ProposalStatus,
        reviewer: Option<String>,
        notes: Option<String>,
    ) -> Result<(), String> {
        let mut guard = self.proposals.write().map_err(|e| e.to_string())?;
        if let Some(proposal) = guard.get_mut(proposal_id) {
            proposal.status = status;
            proposal.reviewed_at = Some(chrono::Utc::now().to_rfc3339());
            proposal.reviewer = reviewer;
            proposal.review_notes = notes;
            Ok(())
        } else {
            Err(format!("proposal {proposal_id} not found"))
        }
    }

    fn list_by_status(&self, status: ProposalStatus) -> Result<Vec<BootstrapProposal>, String> {
        let guard = self.proposals.read().map_err(|e| e.to_string())?;
        Ok(guard
            .values()
            .filter(|p| p.status == status)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_proposal(id: &str, action_type: &str) -> BootstrapProposal {
        BootstrapProposal {
            proposal_id: id.into(),
            action_type: action_type.into(),
            raw_tool_call: json!({"tool": "unknown"}),
            normalizer_yaml: "# normalizer\n".into(),
            risk_rule_yaml: "# risk rule\n".into(),
            reasoning: "LLM reasoning".into(),
            status: ProposalStatus::Pending,
            created_at: "2025-01-01T00:00:00Z".into(),
            reviewed_at: None,
            reviewer: None,
            review_notes: None,
        }
    }

    #[test]
    fn save_and_retrieve() {
        let store = InMemoryProposalStore::new();
        let proposal = make_proposal("p1", "custom.action");
        store.save_proposal(proposal).unwrap();

        let retrieved = store.get_proposal("p1").unwrap().unwrap();
        assert_eq!(retrieved.action_type, "custom.action");
        assert_eq!(retrieved.status, ProposalStatus::Pending);
    }

    #[test]
    fn get_pending_for_action() {
        let store = InMemoryProposalStore::new();
        store
            .save_proposal(make_proposal("p1", "custom.action"))
            .unwrap();

        let pending = store.get_pending_for_action("custom.action").unwrap();
        assert!(pending.is_some());

        let none = store.get_pending_for_action("other.action").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn update_status() {
        let store = InMemoryProposalStore::new();
        store
            .save_proposal(make_proposal("p1", "custom.action"))
            .unwrap();

        store
            .update_status(
                "p1",
                ProposalStatus::Approved,
                Some("admin@example.com".into()),
                Some("LGTM".into()),
            )
            .unwrap();

        let updated = store.get_proposal("p1").unwrap().unwrap();
        assert_eq!(updated.status, ProposalStatus::Approved);
        assert_eq!(updated.reviewer.as_deref(), Some("admin@example.com"));
        assert!(updated.reviewed_at.is_some());

        // No longer pending
        let pending = store.get_pending_for_action("custom.action").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn list_by_status() {
        let store = InMemoryProposalStore::new();
        store
            .save_proposal(make_proposal("p1", "action.a"))
            .unwrap();
        store
            .save_proposal(make_proposal("p2", "action.b"))
            .unwrap();
        store
            .update_status("p2", ProposalStatus::Approved, None, None)
            .unwrap();

        let pending = store.list_by_status(ProposalStatus::Pending).unwrap();
        assert_eq!(pending.len(), 1);

        let approved = store.list_by_status(ProposalStatus::Approved).unwrap();
        assert_eq!(approved.len(), 1);
    }
}
