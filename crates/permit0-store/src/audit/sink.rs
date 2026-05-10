#![forbid(unsafe_code)]

use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// Errors from audit sink operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit sink I/O error: {0}")]
    Io(String),
    #[error("chain verification failed: {0}")]
    ChainBroken(String),
    #[error("audit policy violation: {0}")]
    PolicyViolation(String),
}

/// Pluggable audit sink for persisting and querying audit entries.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    /// Append a single entry.
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError>;

    /// Append a batch of entries.
    async fn append_batch(&self, entries: &[AuditEntry]) -> Result<(), AuditError> {
        for entry in entries {
            self.append(entry).await?;
        }
        Ok(())
    }

    /// Query entries by filter.
    async fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError>;

    /// Verify the hash chain between sequence numbers [from, to].
    async fn verify_chain(&self, from: u64, to: u64) -> Result<ChainVerification, AuditError>;

    /// Return the highest stored `(sequence, entry_hash)`. Used by the
    /// engine on startup to seed its in-process chain head so a daemon
    /// restart doesn't break `prev_hash` linkage. `Ok(None)` means the
    /// sink is empty — engine starts the chain from `GENESIS_HASH`.
    async fn tail(&self) -> Result<Option<(u64, String)>, AuditError>;
}
