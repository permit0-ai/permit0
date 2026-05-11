#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::audit::sink::{AuditError, AuditSink};
use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// Wraps two `AuditSink`s. The primary is the source of truth — the
/// engine's `AuditPolicy` semantics flow through it. The secondary is
/// best-effort: a failure logs and increments a counter but never
/// blocks the primary write or fails the engine call.
///
/// Typical wiring in `serve.rs`:
///
/// ```ignore
/// let primary = Arc::new(PostgresAuditSink::connect(url).await?);
/// let secondary = Arc::new(OtelAuditSink::new(otlp_endpoint, /*fail_open=*/true)?);
/// let sink: Arc<dyn AuditSink> = Arc::new(TeeAuditSink::new(primary, secondary));
/// ```
///
/// Read paths (`query`, `verify_chain`, `tail`) always go to the
/// primary — the secondary is for export, not for the queryable
/// source-of-truth view the dashboard reads.
pub struct TeeAuditSink {
    primary: Arc<dyn AuditSink>,
    secondary: Arc<dyn AuditSink>,
    secondary_failures: AtomicU64,
}

impl TeeAuditSink {
    pub fn new(primary: Arc<dyn AuditSink>, secondary: Arc<dyn AuditSink>) -> Self {
        Self {
            primary,
            secondary,
            secondary_failures: AtomicU64::new(0),
        }
    }

    /// Cumulative count of secondary append failures since process
    /// start. Wire to a Prometheus gauge if you care about drift
    /// between the two sinks.
    pub fn secondary_failures(&self) -> u64 {
        self.secondary_failures.load(Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl AuditSink for TeeAuditSink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        // Primary first — its result decides what the engine sees.
        self.primary.append(entry).await?;

        // Secondary failure must never block the primary write or the
        // engine pipeline. Log + bump the counter and move on.
        if let Err(e) = self.secondary.append(entry).await {
            self.secondary_failures.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                error = %e,
                sequence = entry.sequence,
                "audit secondary sink append failed; primary write succeeded",
            );
        }
        Ok(())
    }

    async fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        self.primary.query(filter).await
    }

    async fn verify_chain(&self, from: u64, to: u64) -> Result<ChainVerification, AuditError> {
        self.primary.verify_chain(from, to).await
    }

    async fn tail(&self) -> Result<Option<(u64, String)>, AuditError> {
        self.primary.tail().await
    }

    async fn query_sequence_range(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        self.primary.query_sequence_range(from, to).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::chain::{GENESIS_HASH, compute_entry_hash};
    use crate::audit::memory_sink::InMemoryAuditSink;
    use crate::audit::signer::{AuditSigner, Ed25519Signer};
    use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission};
    use serde_json::json;

    fn make_entry(seq: u64, signer: &Ed25519Signer) -> AuditEntry {
        let mut e = AuditEntry {
            entry_id: format!("e-{seq}"),
            timestamp: "2026-01-01T00:00:00Z".into(),
            sequence: seq,
            decision: Permission::Allow,
            decision_source: "scorer".into(),
            norm_action: NormAction {
                action_type: ActionType::parse("email.send").unwrap(),
                channel: "test".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "t".into(),
                    surface_command: "c".into(),
                },
            },
            norm_hash: [0u8; 32],
            raw_tool_call: json!({}),
            risk_score: None,
            scoring_detail: None,
            agent_id: String::new(),
            session_id: None,
            task_goal: None,
            org_id: String::new(),
            environment: String::new(),
            engine_version: "0.1".into(),
            pack_id: String::new(),
            pack_version: String::new(),
            dsl_version: "1.0".into(),
            human_review: None,
            engine_decision: None,
            token_id: None,
            prev_hash: GENESIS_HASH.into(),
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: None,
            retroactive_decision: None,
            decision_trace: Vec::new(),
        };
        e.entry_hash = compute_entry_hash(&e);
        e.signature = signer.sign(&e.entry_hash);
        e
    }

    /// AuditSink that always errors on append. Used to verify the tee's
    /// best-effort behavior on the secondary path.
    struct AlwaysFailingSink;

    #[async_trait::async_trait]
    impl AuditSink for AlwaysFailingSink {
        async fn append(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Err(AuditError::Io("simulated failure".into()))
        }
        async fn query(&self, _filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
            Err(AuditError::Io("unsupported".into()))
        }
        async fn verify_chain(
            &self,
            _from: u64,
            _to: u64,
        ) -> Result<ChainVerification, AuditError> {
            Err(AuditError::Io("unsupported".into()))
        }
        async fn tail(&self) -> Result<Option<(u64, String)>, AuditError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn primary_write_wins_secondary_failure() {
        let primary = Arc::new(InMemoryAuditSink::new());
        let secondary = Arc::new(AlwaysFailingSink);
        let tee = TeeAuditSink::new(primary.clone(), secondary);

        let signer = Ed25519Signer::generate();
        let e = make_entry(1, &signer);

        // Append must succeed (primary OK; secondary errored quietly).
        tee.append(&e).await.unwrap();
        assert_eq!(tee.secondary_failures(), 1);

        // Reads come from the primary.
        let all = tee.query(&AuditFilter::default()).await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn primary_failure_propagates() {
        let primary = Arc::new(AlwaysFailingSink);
        let secondary = Arc::new(InMemoryAuditSink::new());
        let tee = TeeAuditSink::new(primary, secondary.clone());

        let signer = Ed25519Signer::generate();
        let e = make_entry(1, &signer);

        assert!(tee.append(&e).await.is_err());
        // Secondary must NOT have been written when the primary fails.
        assert_eq!(secondary.all_entries().len(), 0);
    }

    #[tokio::test]
    async fn both_succeed_writes_to_both() {
        let primary = Arc::new(InMemoryAuditSink::new());
        let secondary = Arc::new(InMemoryAuditSink::new());
        let tee = TeeAuditSink::new(primary.clone(), secondary.clone());

        let signer = Ed25519Signer::generate();
        let e = make_entry(1, &signer);
        tee.append(&e).await.unwrap();

        assert_eq!(primary.all_entries().len(), 1);
        assert_eq!(secondary.all_entries().len(), 1);
        assert_eq!(tee.secondary_failures(), 0);
    }
}
