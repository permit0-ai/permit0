#![forbid(unsafe_code)]

use permit0_types::{DecisionFilter, DecisionRecord, NormHash, Permission};

/// Errors from store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O error: {0}")]
    Io(String),
}

/// Storage interface for denylist, allowlist, policy cache, and decision log.
///
/// All keys are `NormHash` — the SHA-256 of a canonicalized `NormAction`.
/// This trait is object-safe and sync for use behind `Arc<dyn Store>`.
pub trait Store: Send + Sync {
    // ── Denylist ──

    /// Check if a norm_hash is on the denylist. Returns the reason if found.
    fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StoreError>;

    /// Add a norm_hash to the denylist with a reason.
    fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StoreError>;

    /// Remove a norm_hash from the denylist.
    fn denylist_remove(&self, hash: &NormHash) -> Result<(), StoreError>;

    // ── Allowlist ──

    /// Check if a norm_hash is on the allowlist.
    fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StoreError>;

    /// Add a norm_hash to the allowlist with a justification.
    fn allowlist_add(&self, hash: NormHash, justification: String) -> Result<(), StoreError>;

    /// Remove a norm_hash from the allowlist.
    fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StoreError>;

    // ── Policy Cache ──

    /// Get a cached decision for a norm_hash.
    fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StoreError>;

    /// Cache a decision for a norm_hash.
    fn policy_cache_set(&self, hash: NormHash, decision: Permission) -> Result<(), StoreError>;

    /// Clear the entire policy cache.
    fn policy_cache_clear(&self) -> Result<(), StoreError>;

    /// Invalidate a single cache entry.
    fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StoreError>;

    // ── Decision Audit Log ──

    /// Persist a decision record for audit.
    fn save_decision(&self, record: DecisionRecord) -> Result<(), StoreError>;

    /// Query decision records by filter criteria.
    fn query_decisions(&self, filter: &DecisionFilter) -> Result<Vec<DecisionRecord>, StoreError>;
}
