#![forbid(unsafe_code)]

pub mod chain;
pub mod export;
pub mod memory_sink;
pub mod redactor;
pub mod signer;
pub mod sink;
pub mod stdout_sink;
pub mod types;

pub use chain::{compute_entry_hash, verify_chain_link, verify_entry_hash, GENESIS_HASH};
pub use export::{export_csv, export_jsonl};
pub use memory_sink::InMemoryAuditSink;
pub use redactor::{BuiltinRedactor, Redactor};
pub use signer::{AuditSigner, Ed25519Signer, Ed25519Verifier};
pub use sink::{AuditError, AuditSink};
pub use stdout_sink::StdoutAuditSink;
pub use types::{
    AuditEntry, AuditFilter, AuditPolicy, ChainVerification, FailedOpenContext, HumanReview,
    ScoringDetail,
};
