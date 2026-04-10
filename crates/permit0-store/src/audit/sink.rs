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
pub trait AuditSink: Send + Sync {
    /// Append a single entry.
    fn append(&self, entry: &AuditEntry) -> Result<(), AuditError>;

    /// Append a batch of entries.
    fn append_batch(&self, entries: &[AuditEntry]) -> Result<(), AuditError> {
        for entry in entries {
            self.append(entry)?;
        }
        Ok(())
    }

    /// Query entries by filter.
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError>;

    /// Verify the hash chain between sequence numbers [from, to].
    fn verify_chain(&self, from: u64, to: u64) -> Result<ChainVerification, AuditError>;
}
