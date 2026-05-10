#![forbid(unsafe_code)]

use permit0_types::{NormHash, Permission};

/// Errors from policy-state operations.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("policy state I/O error: {0}")]
    Io(String),
}

/// A pending HITL approval row, persisted in the policy state.
///
/// The in-process `oneshot::Sender<HumanDecision>` map (`ApprovalManager`)
/// is keyed by `approval_id` and signals waiters in the engine process;
/// the row here is the durable queue entry that survives a restart and
/// — in a future deployment — can be observed across processes.
#[derive(Debug, Clone)]
pub struct PendingApprovalRow {
    pub approval_id: String,
    pub norm_hash: NormHash,
    pub action_type: String,
    pub channel: String,
    pub created_at: String,
    /// Full normalized action serialized as JSON, so we can reconstruct
    /// the dashboard summary without joining other tables.
    pub norm_action_json: String,
    /// Risk score serialized as JSON.
    pub risk_score_json: String,
}

/// Resolved human decision on a pending approval.
#[derive(Debug, Clone)]
pub struct HumanDecisionRow {
    pub permission: Permission,
    pub reason: String,
    pub reviewer: String,
    pub decided_at: String,
}

/// Policy state: denylist, allowlist, policy cache, and the durable HITL queue.
///
/// Decision log lives only in [`crate::audit::AuditSink`]. Async because
/// the production implementation talks to Postgres via sqlx; the in-memory
/// and rusqlite impls satisfy the trait by running sync bodies inside the
/// async methods (they never yield, which is fine for tests and the
/// offline CLI verifier).
#[async_trait::async_trait]
pub trait PolicyState: Send + Sync {
    // ── Denylist ──

    async fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StateError>;
    async fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StateError>;
    async fn denylist_remove(&self, hash: &NormHash) -> Result<(), StateError>;
    async fn denylist_list(&self) -> Result<Vec<(NormHash, String)>, StateError>;

    // ── Allowlist ──

    async fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StateError>;
    async fn allowlist_add(&self, hash: NormHash, justification: String) -> Result<(), StateError>;
    async fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StateError>;
    async fn allowlist_list(&self) -> Result<Vec<(NormHash, String)>, StateError>;

    // ── Policy cache ──

    async fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StateError>;
    async fn policy_cache_set(
        &self,
        hash: NormHash,
        decision: Permission,
    ) -> Result<(), StateError>;
    async fn policy_cache_clear(&self) -> Result<(), StateError>;
    async fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError>;

    // ── HITL approvals ──

    async fn approval_create(&self, row: PendingApprovalRow) -> Result<(), StateError>;
    async fn approval_get(&self, id: &str) -> Result<Option<PendingApprovalRow>, StateError>;
    async fn approval_resolve(
        &self,
        id: &str,
        decision: HumanDecisionRow,
    ) -> Result<(), StateError>;
    async fn approval_list_pending(&self) -> Result<Vec<PendingApprovalRow>, StateError>;
}
