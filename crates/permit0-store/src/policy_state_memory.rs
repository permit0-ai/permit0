#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use permit0_types::{NormHash, Permission};

use crate::policy_state::{HumanDecisionRow, PendingApprovalRow, PolicyState, StateError};

/// In-memory `PolicyState` for tests, bindings, and ephemeral runs.
/// All data is lost when the process exits.
pub struct InMemoryPolicyState {
    denylist: RwLock<HashMap<NormHash, String>>,
    allowlist: RwLock<HashMap<NormHash, String>>,
    policy_cache: RwLock<HashMap<NormHash, Permission>>,
    pending_approvals: RwLock<HashMap<String, PendingApprovalRow>>,
    resolved_approvals: RwLock<HashMap<String, HumanDecisionRow>>,
}

impl InMemoryPolicyState {
    pub fn new() -> Self {
        Self {
            denylist: RwLock::new(HashMap::new()),
            allowlist: RwLock::new(HashMap::new()),
            policy_cache: RwLock::new(HashMap::new()),
            pending_approvals: RwLock::new(HashMap::new()),
            resolved_approvals: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryPolicyState {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyState for InMemoryPolicyState {
    fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StateError> {
        let g = self
            .denylist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(hash).cloned())
    }

    fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StateError> {
        let mut g = self
            .denylist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, reason);
        Ok(())
    }

    fn denylist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self
            .denylist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    fn denylist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let g = self
            .denylist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StateError> {
        let g = self
            .allowlist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.contains_key(hash))
    }

    fn allowlist_add(&self, hash: NormHash, j: String) -> Result<(), StateError> {
        let mut g = self
            .allowlist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, j);
        Ok(())
    }

    fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self
            .allowlist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    fn allowlist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let g = self
            .allowlist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StateError> {
        let g = self
            .policy_cache
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(hash).copied())
    }

    fn policy_cache_set(&self, hash: NormHash, p: Permission) -> Result<(), StateError> {
        let mut g = self
            .policy_cache
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, p);
        Ok(())
    }

    fn policy_cache_clear(&self) -> Result<(), StateError> {
        let mut g = self
            .policy_cache
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.clear();
        Ok(())
    }

    fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self
            .policy_cache
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    fn approval_create(&self, row: PendingApprovalRow) -> Result<(), StateError> {
        let mut g = self
            .pending_approvals
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(row.approval_id.clone(), row);
        Ok(())
    }

    fn approval_get(&self, id: &str) -> Result<Option<PendingApprovalRow>, StateError> {
        let g = self
            .pending_approvals
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(id).cloned())
    }

    fn approval_resolve(&self, id: &str, decision: HumanDecisionRow) -> Result<(), StateError> {
        let mut pending = self
            .pending_approvals
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        pending.remove(id);
        let mut resolved = self
            .resolved_approvals
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        resolved.insert(id.to_string(), decision);
        Ok(())
    }

    fn approval_list_pending(&self) -> Result<Vec<PendingApprovalRow>, StateError> {
        let g = self
            .pending_approvals
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h() -> NormHash {
        [0u8; 32]
    }

    #[test]
    fn denylist_crud() {
        let s = InMemoryPolicyState::new();
        assert!(s.denylist_check(&h()).unwrap().is_none());
        s.denylist_add(h(), "bad".into()).unwrap();
        assert_eq!(s.denylist_check(&h()).unwrap(), Some("bad".into()));
        s.denylist_remove(&h()).unwrap();
        assert!(s.denylist_check(&h()).unwrap().is_none());
    }

    #[test]
    fn allowlist_crud() {
        let s = InMemoryPolicyState::new();
        assert!(!s.allowlist_check(&h()).unwrap());
        s.allowlist_add(h(), "ok".into()).unwrap();
        assert!(s.allowlist_check(&h()).unwrap());
    }

    #[test]
    fn policy_cache_crud() {
        let s = InMemoryPolicyState::new();
        assert!(s.policy_cache_get(&h()).unwrap().is_none());
        s.policy_cache_set(h(), Permission::Allow).unwrap();
        assert_eq!(s.policy_cache_get(&h()).unwrap(), Some(Permission::Allow));
        s.policy_cache_invalidate(&h()).unwrap();
        assert!(s.policy_cache_get(&h()).unwrap().is_none());
    }

    #[test]
    fn approval_lifecycle() {
        let s = InMemoryPolicyState::new();
        let row = PendingApprovalRow {
            approval_id: "abc".into(),
            norm_hash: h(),
            action_type: "email.send".into(),
            channel: "gmail".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            norm_action_json: "{}".into(),
            risk_score_json: "{}".into(),
        };
        s.approval_create(row).unwrap();
        assert!(s.approval_get("abc").unwrap().is_some());
        assert_eq!(s.approval_list_pending().unwrap().len(), 1);

        s.approval_resolve(
            "abc",
            HumanDecisionRow {
                permission: Permission::Allow,
                reason: "ok".into(),
                reviewer: "alice".into(),
                decided_at: "2026-01-01T00:01:00Z".into(),
            },
        )
        .unwrap();
        assert!(s.approval_get("abc").unwrap().is_none());
        assert_eq!(s.approval_list_pending().unwrap().len(), 0);
    }
}
