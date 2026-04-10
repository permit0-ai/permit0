#![forbid(unsafe_code)]

use std::sync::RwLock;

use permit0_types::NormHash;

use super::types::HumanOverride;

/// Storage for human overrides, separate from the main Store.
pub trait OverrideStore: Send + Sync {
    /// Record a human override.
    fn record_override(&self, override_record: HumanOverride) -> Result<(), String>;

    /// Get all overrides for a given norm_hash.
    fn get_overrides(&self, norm_hash: &NormHash) -> Result<Vec<HumanOverride>, String>;

    /// Get all overrides for a given action type.
    fn get_overrides_by_action(&self, action_type: &str) -> Result<Vec<HumanOverride>, String>;

    /// Count total overrides for an action type.
    fn count_overrides(&self, action_type: &str) -> Result<u64, String>;
}

/// In-memory override store for testing.
pub struct InMemoryOverrideStore {
    overrides: RwLock<Vec<HumanOverride>>,
}

impl InMemoryOverrideStore {
    pub fn new() -> Self {
        Self {
            overrides: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryOverrideStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OverrideStore for InMemoryOverrideStore {
    fn record_override(&self, override_record: HumanOverride) -> Result<(), String> {
        let mut guard = self.overrides.write().map_err(|e| e.to_string())?;
        guard.push(override_record);
        Ok(())
    }

    fn get_overrides(&self, norm_hash: &NormHash) -> Result<Vec<HumanOverride>, String> {
        let guard = self.overrides.read().map_err(|e| e.to_string())?;
        Ok(guard
            .iter()
            .filter(|o| o.norm_hash == *norm_hash)
            .cloned()
            .collect())
    }

    fn get_overrides_by_action(&self, action_type: &str) -> Result<Vec<HumanOverride>, String> {
        let guard = self.overrides.read().map_err(|e| e.to_string())?;
        Ok(guard
            .iter()
            .filter(|o| o.action_type == action_type)
            .cloned()
            .collect())
    }

    fn count_overrides(&self, action_type: &str) -> Result<u64, String> {
        let guard = self.overrides.read().map_err(|e| e.to_string())?;
        Ok(guard
            .iter()
            .filter(|o| o.action_type == action_type)
            .count() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_types::Permission;

    fn make_override(action_type: &str, norm_hash: NormHash) -> HumanOverride {
        HumanOverride {
            original_decision: Permission::HumanInTheLoop,
            human_decision: Permission::Allow,
            norm_hash,
            action_type: action_type.into(),
            reason: "Reviewed and approved".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reviewer: "alice@example.com".into(),
        }
    }

    #[test]
    fn record_and_retrieve_by_hash() {
        let store = InMemoryOverrideStore::new();
        let hash = [1u8; 32];
        store.record_override(make_override("email.send", hash)).unwrap();
        store.record_override(make_override("email.send", [2u8; 32])).unwrap();

        let results = store.get_overrides(&hash).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].norm_hash, hash);
    }

    #[test]
    fn retrieve_by_action_type() {
        let store = InMemoryOverrideStore::new();
        store.record_override(make_override("email.send", [1u8; 32])).unwrap();
        store.record_override(make_override("email.send", [2u8; 32])).unwrap();
        store.record_override(make_override("payments.charge", [3u8; 32])).unwrap();

        let email_overrides = store.get_overrides_by_action("email.send").unwrap();
        assert_eq!(email_overrides.len(), 2);

        let payment_overrides = store.get_overrides_by_action("payments.charge").unwrap();
        assert_eq!(payment_overrides.len(), 1);
    }

    #[test]
    fn count_overrides() {
        let store = InMemoryOverrideStore::new();
        store.record_override(make_override("email.send", [1u8; 32])).unwrap();
        store.record_override(make_override("email.send", [2u8; 32])).unwrap();

        assert_eq!(store.count_overrides("email.send").unwrap(), 2);
        assert_eq!(store.count_overrides("payments.charge").unwrap(), 0);
    }
}
