#![forbid(unsafe_code)]

pub mod chain;
pub mod export;
pub mod key_store;
pub mod memory_sink;
pub mod pg_sink;
pub mod redactor;
pub mod signer;
pub mod sink;
pub mod sqlite_sink;
pub mod stdout_sink;
pub mod types;

pub use chain::{GENESIS_HASH, compute_entry_hash, verify_chain_link, verify_entry_hash};
pub use export::{export_csv, export_jsonl};
pub use key_store::{FileKeyStore, KeyStoreError};
pub use memory_sink::InMemoryAuditSink;
pub use pg_sink::PostgresAuditSink;
pub use redactor::{BuiltinRedactor, Redactor};
pub use signer::{AuditSigner, Ed25519Signer, Ed25519Verifier};
pub use sink::{AuditError, AuditSink};
pub use sqlite_sink::SqliteAuditSink;
pub use stdout_sink::StdoutAuditSink;
pub use types::{
    AuditEntry, AuditFilter, AuditPolicy, ChainVerification, DecisionStage, FailedOpenContext,
    HumanReview, ScoringDetail,
};
