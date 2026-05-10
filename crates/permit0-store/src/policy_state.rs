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
/// Decision log lives only in [`crate::audit::AuditSink`]. This trait is
/// sync in PR 1 to keep `Engine::get_permission` synchronous (the bindings
/// in `permit0-py` and `permit0-node` call it directly). PR 2 introduces
/// an async variant alongside the Postgres implementation.
pub trait PolicyState: Send + Sync {
    // ── Denylist ──

    fn denylist_check(&self, hash: &NormHash) -> Result<Option<String>, StateError>;
    fn denylist_add(&self, hash: NormHash, reason: String) -> Result<(), StateError>;
    fn denylist_remove(&self, hash: &NormHash) -> Result<(), StateError>;
    fn denylist_list(&self) -> Result<Vec<(NormHash, String)>, StateError>;

    // ── Allowlist ──

    fn allowlist_check(&self, hash: &NormHash) -> Result<bool, StateError>;
    fn allowlist_add(&self, hash: NormHash, justification: String) -> Result<(), StateError>;
    fn allowlist_remove(&self, hash: &NormHash) -> Result<(), StateError>;
    fn allowlist_list(&self) -> Result<Vec<(NormHash, String)>, StateError>;

    // ── Policy cache ──

    fn policy_cache_get(&self, hash: &NormHash) -> Result<Option<Permission>, StateError>;
    fn policy_cache_set(&self, hash: NormHash, decision: Permission) -> Result<(), StateError>;
    fn policy_cache_clear(&self) -> Result<(), StateError>;
    fn policy_cache_invalidate(&self, hash: &NormHash) -> Result<(), StateError>;

    // ── HITL approvals ──
    //
    // PR 1 wires the schema; the in-process `ApprovalManager` continues
    // to own the `oneshot::Sender` map. PR 2 routes `create_pending` /
    // `submit_decision` through these methods so the queue survives a
    // restart and can be inspected by other replicas.

    fn approval_create(&self, row: PendingApprovalRow) -> Result<(), StateError>;
    fn approval_get(&self, id: &str) -> Result<Option<PendingApprovalRow>, StateError>;
    fn approval_resolve(&self, id: &str, decision: HumanDecisionRow) -> Result<(), StateError>;
    fn approval_list_pending(&self) -> Result<Vec<PendingApprovalRow>, StateError>;
}
