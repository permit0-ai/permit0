#![forbid(unsafe_code)]

pub mod chain;
pub mod digest;
pub mod digest_writer;
pub mod export;
pub mod key_store;
pub mod memory_sink;
pub mod otel_sink;
pub mod pg_sink;
pub mod redactor;
pub mod signer;
pub mod sink;
pub mod sqlite_sink;
pub mod stdout_sink;
pub mod tee_sink;
pub mod types;

pub use chain::{
    GENESIS_HASH, compute_digest_hash, compute_entry_hash, compute_entry_hashes_root,
    verify_chain_link, verify_digest_hash, verify_digest_link, verify_entry_hash,
};
pub use digest::{Digest, DigestStore, GENESIS_DIGEST_HASH};
pub use digest_writer::{DigestWriter, FileDigestStore};
pub use export::{export_csv, export_jsonl};
pub use key_store::{FileKeyStore, KeyStoreError};
pub use memory_sink::InMemoryAuditSink;
pub use otel_sink::OtelAuditSink;
pub use pg_sink::PostgresAuditSink;
pub use redactor::{BuiltinRedactor, Redactor};
pub use signer::{AuditSigner, Ed25519Signer, Ed25519Verifier};
pub use sink::{AuditError, AuditSink};
pub use sqlite_sink::SqliteAuditSink;
pub use stdout_sink::StdoutAuditSink;
pub use tee_sink::TeeAuditSink;
pub use types::{
    AuditEntry, AuditFilter, AuditPolicy, ChainVerification, DecisionStage, FailedOpenContext,
    HumanReview, ScoringDetail,
};
