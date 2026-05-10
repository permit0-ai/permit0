#![forbid(unsafe_code)]
#![doc = "Storage traits and implementations for permit0."]

pub mod audit;
mod pg_state;
mod policy_state;
mod policy_state_memory;
mod policy_state_sqlite;

pub use pg_state::PostgresPolicyState;
pub use policy_state::{HumanDecisionRow, PendingApprovalRow, PolicyState, StateError};
pub use policy_state_memory::InMemoryPolicyState;
pub use policy_state_sqlite::SqlitePolicyState;

// Re-export key audit types at crate root for convenience.
pub use audit::{
    AuditEntry, AuditError, AuditFilter, AuditPolicy, AuditSigner, AuditSink, BuiltinRedactor,
    ChainVerification, DecisionStage, Ed25519Signer, Ed25519Verifier, FileKeyStore, HumanReview,
    InMemoryAuditSink, KeyStoreError, PostgresAuditSink, Redactor, ScoringDetail, SqliteAuditSink,
    StdoutAuditSink,
};
