#![forbid(unsafe_code)]
#![doc = "Storage traits and implementations for permit0."]

pub mod audit;
mod pg_state;
mod policy_state;
mod policy_state_memory;
mod policy_state_sqlite;

/// Current Unix time in whole seconds. Shared by the policy-state impls
/// for cache TTL bookkeeping.
pub(crate) fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub use pg_state::PostgresPolicyState;
pub use policy_state::{HumanDecisionRow, PendingApprovalRow, PolicyState, StateError};
pub use policy_state_memory::InMemoryPolicyState;
pub use policy_state_sqlite::SqlitePolicyState;

// Re-export key audit types at crate root for convenience.
pub use audit::pg_sink::PostgresDigestStore;
pub use audit::{
    AuditEntry, AuditError, AuditFilter, AuditPolicy, AuditSigner, AuditSink, BuiltinRedactor,
    ChainVerification, DecisionStage, Digest, DigestStore, DigestWriter, Ed25519Signer,
    Ed25519Verifier, FileDigestStore, FileKeyStore, HumanReview, InMemoryAuditSink, KeyStoreError,
    OtelAuditSink, PostgresAuditSink, Redactor, ScoringDetail, SqliteAuditSink, StdoutAuditSink,
    TeeAuditSink,
};
