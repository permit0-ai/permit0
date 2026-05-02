#![forbid(unsafe_code)]
#![doc = "Storage traits and implementations for permit0."]

pub mod audit;
mod memory;
mod sqlite;
mod traits;

pub use memory::InMemoryStore;
pub use sqlite::SqliteStore;
pub use traits::{Store, StoreError};

// Re-export key audit types at crate root for convenience.
pub use audit::{
    AuditEntry, AuditError, AuditFilter, AuditPolicy, AuditSigner, AuditSink, BuiltinRedactor,
    ChainVerification, DecisionStage, Ed25519Signer, Ed25519Verifier, HumanReview,
    InMemoryAuditSink, Redactor, ScoringDetail, StdoutAuditSink,
};
