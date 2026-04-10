#![forbid(unsafe_code)]

use crate::audit::sink::{AuditError, AuditSink};
use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// Stdout audit sink — writes JSONL to stdout for piping to SIEM
/// (Splunk, Datadog, Elastic).
pub struct StdoutAuditSink;

impl StdoutAuditSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdoutAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for StdoutAuditSink {
    fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let json = serde_json::to_string(entry)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        println!("{json}");
        Ok(())
    }

    fn query(&self, _filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        Err(AuditError::Io(
            "StdoutAuditSink does not support queries".into(),
        ))
    }

    fn verify_chain(&self, _from: u64, _to: u64) -> Result<ChainVerification, AuditError> {
        Err(AuditError::Io(
            "StdoutAuditSink does not support chain verification".into(),
        ))
    }
}
