#![forbid(unsafe_code)]

use std::time::SystemTime;

use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::{Logger as SdkLogger, LoggerProvider as SdkLoggerProvider};
use opentelemetry_sdk::runtime::Tokio;

use crate::audit::sink::{AuditError, AuditSink};
use crate::audit::types::{AuditEntry, AuditFilter, ChainVerification};

/// Audit sink that ships every entry to an OpenTelemetry collector
/// (typically batched + forwarded to S3 / Datadog / Splunk).
///
/// Wrap with [`super::tee_sink::TeeAuditSink`]:
///
/// ```ignore
/// let primary  = Arc::new(PostgresAuditSink::connect(url).await?);
/// let secondary = Arc::new(OtelAuditSink::http("http://collector:4318", true)?);
/// let sink: Arc<dyn AuditSink> = Arc::new(TeeAuditSink::new(primary, secondary));
/// ```
///
/// Read paths (`query`, `verify_chain`, `tail`) are intentionally
/// unsupported — OTel is a write-only export. Use the local
/// Postgres sink (the tee primary) for queries.
pub struct OtelAuditSink {
    logger: SdkLogger,
    /// When `true`, append errors are logged + swallowed and the call
    /// returns `Ok(())`. Mostly relevant inside a `TeeAuditSink` where
    /// the secondary's failures are already swallowed — but a direct
    /// caller can opt to fail the engine if the OTel collector is the
    /// only durable sink.
    fail_open: bool,
    /// Held to keep the SDK's batch processor alive for the lifetime
    /// of the sink; dropped on `Drop`. The shutdown blocks the current
    /// thread for up to a few seconds while the batch processor
    /// flushes; that's intentional so a clean engine shutdown doesn't
    /// silently drop in-flight audit records.
    _provider: SdkLoggerProvider,
}

impl OtelAuditSink {
    /// Build an OTLP/HTTP sink pointing at `endpoint` (e.g.
    /// `http://otel-collector:4318`). The exporter speaks
    /// protobuf-over-HTTP; OTLP/gRPC is not enabled in this build to
    /// keep the dependency footprint small.
    pub fn http(endpoint: &str, fail_open: bool) -> Result<Self, AuditError> {
        let exporter: LogExporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| AuditError::Io(format!("build OTLP log exporter: {e}")))?;

        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter, Tokio)
            .build();

        let logger = provider.logger("permit0.audit");
        Ok(Self {
            logger,
            fail_open,
            _provider: provider,
        })
    }
}

fn permission_str(p: permit0_types::Permission) -> &'static str {
    match p {
        permit0_types::Permission::Allow => "allow",
        permit0_types::Permission::HumanInTheLoop => "human",
        permit0_types::Permission::Deny => "deny",
    }
}

fn severity_for(p: permit0_types::Permission) -> Severity {
    match p {
        permit0_types::Permission::Allow => Severity::Info,
        permit0_types::Permission::HumanInTheLoop => Severity::Warn,
        permit0_types::Permission::Deny => Severity::Error,
    }
}

#[async_trait::async_trait]
impl AuditSink for OtelAuditSink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut rec = self.logger.create_log_record();

        // Severity tracks decision: allow=info, human=warn, deny=error.
        rec.set_severity_text(permission_str(entry.decision));
        rec.set_severity_number(severity_for(entry.decision));
        rec.set_event_name("permit0.audit.entry");

        // Use observed timestamp = now; original wall-clock is in
        // attributes so the collector pipeline can pick whichever it
        // prefers without losing fidelity.
        rec.set_observed_timestamp(SystemTime::now());

        // Body = the full AuditEntry as JSON. Some collectors (Datadog,
        // Splunk) treat the body as the searchable record; others (S3
        // exporter) write it straight to the bucket. Either way, the
        // forensic content is in one place.
        let body = serde_json::to_string(entry)
            .map_err(|e| AuditError::Io(format!("serialize audit entry: {e}")))?;
        rec.set_body(AnyValue::String(body.into()));

        // Indexable attributes for fast search in collector backends.
        rec.add_attribute("permit0.entry_id", entry.entry_id.clone());
        rec.add_attribute("permit0.sequence", entry.sequence as i64);
        rec.add_attribute("permit0.timestamp", entry.timestamp.clone());
        rec.add_attribute("permit0.decision", permission_str(entry.decision));
        rec.add_attribute(
            "permit0.action_type",
            entry.norm_action.action_type.as_action_str(),
        );
        rec.add_attribute("permit0.channel", entry.norm_action.channel.clone());
        if let Some(ref sid) = entry.session_id {
            rec.add_attribute("permit0.session_id", sid.clone());
        }
        if let Some(ref rs) = entry.risk_score {
            rec.add_attribute("permit0.tier", format!("{:?}", rs.tier));
            rec.add_attribute("permit0.risk_raw", rs.raw);
        }
        // Chain integrity surfaces — let the collector index them so
        // operators can join the OTel stream against a Postgres dump.
        rec.add_attribute("permit0.prev_hash", entry.prev_hash.clone());
        rec.add_attribute("permit0.entry_hash", entry.entry_hash.clone());
        rec.add_attribute("permit0.signature", entry.signature.clone());

        self.logger.emit(rec);

        // The SDK exporter is asynchronous (batched). `emit` doesn't
        // surface per-call I/O errors — the batch processor logs and
        // drops on transport failure. That matches the secondary-sink
        // semantics in TeeAuditSink. If `fail_open` is false we still
        // honor it for symmetry; today this branch is dead code.
        if !self.fail_open {
            // Future: if/when we add a synchronous flush hook, call it
            // here and propagate its error. For now, emit() is fire-
            // and-forget, so this path is no different from fail_open.
        }
        Ok(())
    }

    async fn query(&self, _filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        Err(AuditError::Io(
            "OtelAuditSink does not support queries — use the primary (Postgres) sink".into(),
        ))
    }

    async fn verify_chain(&self, _from: u64, _to: u64) -> Result<ChainVerification, AuditError> {
        Err(AuditError::Io(
            "OtelAuditSink does not support chain verification — use the primary sink".into(),
        ))
    }

    async fn tail(&self) -> Result<Option<(u64, String)>, AuditError> {
        // Write-only sink — no head to seed from.
        Ok(None)
    }
}
