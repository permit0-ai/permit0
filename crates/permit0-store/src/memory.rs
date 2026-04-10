#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use permit0_types::{DecisionFilter, DecisionRecord, NormHash, Permission};

use crate::traits::{Store, StoreError};

/// In-memory store for testing and development.
/// All data is lost when the process exits.
pub struct InMemoryStore {
    denylist: RwLock<HashMap<NormHash, String>>,
    allowlist: RwLock<HashMap<NormHash, String>>,
    policy_cache: RwLock<HashMap<NormHash, Permission>>,
    decisions: RwLock<Vec<DecisionRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            denylist: RwLock::new(HashMap::new()),
            allowlist: RwLock::new(HashMap::new()),
            policy_cache: RwLock::new(HashMap::new()),
            decisions: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for InMemoryStore {
    fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StoreError> {
        let guard = self.denylist.read().map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(guard.get(hash).cloned())
    }

    fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StoreError> {
        let mut guard = self.denylist.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.insert(hash, reason);
        Ok(())
    }

    fn denylist_remove(&self, hash: &NormHash) -> Result<(), StoreError> {
        let mut guard = self.denylist.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.remove(hash);
        Ok(())
    }

    fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StoreError> {
        let guard = self.allowlist.read().map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(guard.contains_key(hash))
    }

    fn allowlist_add(&self, hash: NormHash, justification: String) -> Result<(), StoreError> {
        let mut guard = self.allowlist.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.insert(hash, justification);
        Ok(())
    }

    fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StoreError> {
        let mut guard = self.allowlist.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.remove(hash);
        Ok(())
    }

    fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StoreError> {
        let guard = self.policy_cache.read().map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(guard.get(hash).copied())
    }

    fn policy_cache_set(&self, hash: NormHash, decision: Permission) -> Result<(), StoreError> {
        let mut guard = self.policy_cache.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.insert(hash, decision);
        Ok(())
    }

    fn policy_cache_clear(&self) -> Result<(), StoreError> {
        let mut guard = self.policy_cache.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.clear();
        Ok(())
    }

    fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StoreError> {
        let mut guard = self.policy_cache.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.remove(hash);
        Ok(())
    }

    fn save_decision(&self, record: DecisionRecord) -> Result<(), StoreError> {
        let mut guard = self.decisions.write().map_err(|e| StoreError::Io(e.to_string()))?;
        guard.push(record);
        Ok(())
    }

    fn query_decisions(&self, filter: &DecisionFilter) -> Result<Vec<DecisionRecord>, StoreError> {
        let guard = self.decisions.read().map_err(|e| StoreError::Io(e.to_string()))?;
        let limit = filter.limit.unwrap_or(100) as usize;

        let results: Vec<DecisionRecord> = guard
            .iter()
            .rev() // newest first
            .filter(|r| {
                if let Some(ref at) = filter.action_type {
                    if !r.action_type.starts_with(at.as_str()) {
                        return false;
                    }
                }
                if let Some(ref perm) = filter.permission {
                    if r.permission != *perm {
                        return false;
                    }
                }
                if let Some(ref ch) = filter.channel {
                    if r.channel != *ch {
                        return false;
                    }
                }
                if let Some(ref since) = filter.since {
                    if r.timestamp.as_str() < since.as_str() {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect();

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash() -> NormHash {
        [0u8; 32]
    }

    fn other_hash() -> NormHash {
        let mut h = [0u8; 32];
        h[0] = 1;
        h
    }

    #[test]
    fn denylist_crud() {
        let store = InMemoryStore::new();
        assert!(store.denylist_check(&dummy_hash()).unwrap().is_none());

        store.denylist_add(dummy_hash(), "bad".into()).unwrap();
        assert_eq!(
            store.denylist_check(&dummy_hash()).unwrap(),
            Some("bad".into())
        );

        store.denylist_remove(&dummy_hash()).unwrap();
        assert!(store.denylist_check(&dummy_hash()).unwrap().is_none());
    }

    #[test]
    fn allowlist_crud() {
        let store = InMemoryStore::new();
        assert!(!store.allowlist_check(&dummy_hash()).unwrap());

        store.allowlist_add(dummy_hash(), "safe".into()).unwrap();
        assert!(store.allowlist_check(&dummy_hash()).unwrap());

        store.allowlist_remove(&dummy_hash()).unwrap();
        assert!(!store.allowlist_check(&dummy_hash()).unwrap());
    }

    #[test]
    fn policy_cache_crud() {
        let store = InMemoryStore::new();
        assert!(store.policy_cache_get(&dummy_hash()).unwrap().is_none());

        store
            .policy_cache_set(dummy_hash(), Permission::Allow)
            .unwrap();
        assert_eq!(
            store.policy_cache_get(&dummy_hash()).unwrap(),
            Some(Permission::Allow)
        );

        store.policy_cache_invalidate(&dummy_hash()).unwrap();
        assert!(store.policy_cache_get(&dummy_hash()).unwrap().is_none());
    }

    fn test_decision(action_type: &str, permission: Permission, channel: &str, ts: &str) -> DecisionRecord {
        DecisionRecord {
            id: format!("test-{ts}"),
            norm_hash: dummy_hash(),
            action_type: action_type.into(),
            channel: channel.into(),
            permission,
            source: "scorer".into(),
            tier: None,
            risk_raw: None,
            blocked: false,
            flags: vec![],
            timestamp: ts.into(),
            surface_tool: "test".into(),
            surface_command: "test".into(),
        }
    }

    #[test]
    fn decision_save_and_query() {
        let store = InMemoryStore::new();
        store
            .save_decision(test_decision("payments.charge", Permission::Allow, "stripe", "2025-01-01T00:00:00Z"))
            .unwrap();
        store
            .save_decision(test_decision("email.send", Permission::Deny, "gmail", "2025-01-02T00:00:00Z"))
            .unwrap();

        let all = store.query_decisions(&DecisionFilter::default()).unwrap();
        assert_eq!(all.len(), 2);
        // Newest first
        assert_eq!(all[0].action_type, "email.send");
        assert_eq!(all[1].action_type, "payments.charge");
    }

    #[test]
    fn decision_query_with_filter() {
        let store = InMemoryStore::new();
        store
            .save_decision(test_decision("payments.charge", Permission::Allow, "stripe", "2025-01-01T00:00:00Z"))
            .unwrap();
        store
            .save_decision(test_decision("payments.refund", Permission::Deny, "stripe", "2025-01-02T00:00:00Z"))
            .unwrap();
        store
            .save_decision(test_decision("email.send", Permission::Allow, "gmail", "2025-01-03T00:00:00Z"))
            .unwrap();

        // Filter by action_type prefix
        let payments = store
            .query_decisions(&DecisionFilter {
                action_type: Some("payments".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(payments.len(), 2);

        // Filter by permission
        let denies = store
            .query_decisions(&DecisionFilter {
                permission: Some(Permission::Deny),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].action_type, "payments.refund");

        // Filter by channel
        let gmail = store
            .query_decisions(&DecisionFilter {
                channel: Some("gmail".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(gmail.len(), 1);

        // Limit
        let limited = store
            .query_decisions(&DecisionFilter {
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn policy_cache_clear_removes_all() {
        let store = InMemoryStore::new();
        store
            .policy_cache_set(dummy_hash(), Permission::Allow)
            .unwrap();
        store
            .policy_cache_set(other_hash(), Permission::Deny)
            .unwrap();

        store.policy_cache_clear().unwrap();
        assert!(store.policy_cache_get(&dummy_hash()).unwrap().is_none());
        assert!(store.policy_cache_get(&other_hash()).unwrap().is_none());
    }
}
