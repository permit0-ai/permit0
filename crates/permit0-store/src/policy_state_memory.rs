#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use permit0_types::{NormHash, Permission, RiskScore};

use crate::now_epoch;
use crate::policy_state::{
    CachedDecision, HumanDecisionRow, PendingApprovalRow, PolicyState, StateError,
};

/// (permission, risk_score, created_at_epoch_secs)
type CacheEntry = (Permission, Option<RiskScore>, i64);

/// In-memory `PolicyState` for tests, bindings, and ephemeral runs.
/// All data is lost when the process exits.
pub struct InMemoryPolicyState {
    denylist: RwLock<HashMap<NormHash, String>>,
    allowlist: RwLock<HashMap<NormHash, String>>,
    policy_cache: RwLock<HashMap<NormHash, CacheEntry>>,
    cache_meta: RwLock<HashMap<String, String>>,
    pending_approvals: RwLock<HashMap<String, PendingApprovalRow>>,
    resolved_approvals: RwLock<HashMap<String, HumanDecisionRow>>,
}

impl InMemoryPolicyState {
    pub fn new() -> Self {
        Self {
            denylist: RwLock::new(HashMap::new()),
            allowlist: RwLock::new(HashMap::new()),
            policy_cache: RwLock::new(HashMap::new()),
            cache_meta: RwLock::new(HashMap::new()),
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

#[async_trait::async_trait]
impl PolicyState for InMemoryPolicyState {
    async fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StateError> {
        let g = self
            .denylist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(hash).cloned())
    }

    async fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StateError> {
        let mut g = self
            .denylist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, reason);
        Ok(())
    }

    async fn denylist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self
            .denylist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    async fn denylist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let g = self
            .denylist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    async fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StateError> {
        let g = self
            .allowlist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.contains_key(hash))
    }

    async fn allowlist_add(&self, hash: NormHash, j: String) -> Result<(), StateError> {
        let mut g = self
            .allowlist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, j);
        Ok(())
    }

    async fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self
            .allowlist
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    async fn allowlist_list(&self) -> Result<Vec<(NormHash, String)>, StateError> {
        let g = self
            .allowlist
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    async fn policy_cache_get(
        &self,
        hash: &NormHash,
        ttl_secs: i64,
    ) -> Result<Option<CachedDecision>, StateError> {
        let cutoff = now_epoch() - ttl_secs;
        let g = self
            .policy_cache
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(hash)
            .filter(|(_, _, ts)| *ts > cutoff)
            .map(|(perm, rs, _)| CachedDecision {
                permission: *perm,
                risk_score: rs.clone(),
            }))
    }

    async fn policy_cache_set(
        &self,
        hash: NormHash,
        p: Permission,
        risk_score: Option<RiskScore>,
    ) -> Result<(), StateError> {
        let mut g = self
            .policy_cache
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(hash, (p, risk_score, now_epoch()));
        Ok(())
    }

    async fn policy_cache_clear(&self) -> Result<(), StateError> {
        let mut g = self
            .policy_cache
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.clear();
        Ok(())
    }

    async fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError> {
        let mut g = self
            .policy_cache
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.remove(hash);
        Ok(())
    }

    async fn cache_meta_get(&self, key: &str) -> Result<Option<String>, StateError> {
        let g = self
            .cache_meta
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(key).cloned())
    }

    async fn cache_meta_set(&self, key: &str, value: &str) -> Result<(), StateError> {
        let mut g = self
            .cache_meta
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn approval_create(&self, row: PendingApprovalRow) -> Result<(), StateError> {
        let mut g = self
            .pending_approvals
            .write()
            .map_err(|e| StateError::Io(e.to_string()))?;
        g.insert(row.approval_id.clone(), row);
        Ok(())
    }

    async fn approval_get(&self, id: &str) -> Result<Option<PendingApprovalRow>, StateError> {
        let g = self
            .pending_approvals
            .read()
            .map_err(|e| StateError::Io(e.to_string()))?;
        Ok(g.get(id).cloned())
    }

    async fn approval_resolve(
        &self,
        id: &str,
        decision: HumanDecisionRow,
    ) -> Result<(), StateError> {
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

    async fn approval_list_pending(&self) -> Result<Vec<PendingApprovalRow>, StateError> {
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

    #[tokio::test]
    async fn denylist_crud() {
        let s = InMemoryPolicyState::new();
        assert!(s.denylist_check(&h()).await.unwrap().is_none());
        s.denylist_add(h(), "bad".into()).await.unwrap();
        assert_eq!(s.denylist_check(&h()).await.unwrap(), Some("bad".into()));
        s.denylist_remove(&h()).await.unwrap();
        assert!(s.denylist_check(&h()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn allowlist_crud() {
        let s = InMemoryPolicyState::new();
        assert!(!s.allowlist_check(&h()).await.unwrap());
        s.allowlist_add(h(), "ok".into()).await.unwrap();
        assert!(s.allowlist_check(&h()).await.unwrap());
    }

    #[tokio::test]
    async fn policy_cache_crud() {
        let s = InMemoryPolicyState::new();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_none());
        s.policy_cache_set(h(), Permission::Allow, None)
            .await
            .unwrap();
        assert_eq!(
            s.policy_cache_get(&h(), 3600)
                .await
                .unwrap()
                .map(|c| c.permission),
            Some(Permission::Allow)
        );
        s.policy_cache_invalidate(&h()).await.unwrap();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn policy_cache_ttl_expires() {
        let s = InMemoryPolicyState::new();
        s.policy_cache_set(h(), Permission::Allow, None)
            .await
            .unwrap();
        assert!(s.policy_cache_get(&h(), 3600).await.unwrap().is_some());
        // A TTL of -1 puts the cutoff in the future → entry is expired.
        assert!(s.policy_cache_get(&h(), -1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn approval_lifecycle() {
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
        s.approval_create(row).await.unwrap();
        assert!(s.approval_get("abc").await.unwrap().is_some());
        assert_eq!(s.approval_list_pending().await.unwrap().len(), 1);

        s.approval_resolve(
            "abc",
            HumanDecisionRow {
                permission: Permission::Allow,
                reason: "ok".into(),
                reviewer: "alice".into(),
                decided_at: "2026-01-01T00:01:00Z".into(),
            },
        )
        .await
        .unwrap();
        assert!(s.approval_get("abc").await.unwrap().is_none());
        assert_eq!(s.approval_list_pending().await.unwrap().len(), 0);
    }
}
