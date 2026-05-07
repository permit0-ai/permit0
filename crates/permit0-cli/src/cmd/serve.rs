#![forbid(unsafe_code)]

//! HTTP server mode: `permit0 serve --port 9090`.
//!
//! Exposes a REST API for remote agents:
//!
//! - `POST /api/v1/check` — evaluate a tool call, return decision JSON
//! - `GET  /api/v1/health` — health check
//!
//! Also mounts the full approval UI API if `--ui` is passed.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use permit0_engine::{DecisionSource, Engine, PermissionCtx, PermissionResult};
use permit0_normalize::NormalizeCtx;
use permit0_session::SessionContext;
use permit0_store::audit::{
    AuditSigner, AuditSink, Ed25519Signer, FailedOpenContext, InMemoryAuditSink,
};
use permit0_store::{InMemoryStore, SqliteStore, Store};
use permit0_types::{
    ActionType, DecisionRecord, Entities, ExecutionMeta, NormAction, RawToolCall, RiskScore, Tier,
};
use permit0_ui::{AppState, ApprovalManager, TokenStore};
use tower_http::services::ServeDir;

use crate::cmd::hook::ClientKind;
use crate::engine_factory;
use std::str::FromStr;

/// Shared state for the server.
#[derive(Clone)]
struct ServerState {
    engine: Arc<Engine>,
    org_domain: String,
    store: Option<Arc<dyn Store>>,
    /// Calibration mode: every fresh decision is escalated to human approval.
    calibrate: bool,
    /// Approval manager for the calibration synchronous wait. Shared with
    /// AppState so the dashboard's /api/v1/approvals/decide endpoint
    /// resolves the same channel.
    approval_manager: Option<Arc<permit0_ui::ApprovalManager>>,
}

/// Request body for POST /api/v1/check.
///
/// `metadata` is a free-form map carrying caller-supplied context that
/// lands on the audit entry. The handler extracts the well-known keys
/// `session_id` and `task_goal` to populate `AuditEntry.session_id` and
/// `AuditEntry.task_goal`. Unknown keys round-trip into the engine as
/// part of `RawToolCall.metadata` and are available to normalizers/risk
/// rules that opt in to consuming them.
///
/// `client_kind` selects host-specific tool-name prefix stripping. See
/// [`ClientKind`] for the supported values. When omitted (or invalid),
/// the handler falls back to no stripping (`Raw`) — clients that already
/// pass bare tool names work without setting it. As a backwards-compat
/// fallback, the handler also reads `metadata.client_kind` (where older
/// clients stamped it) before defaulting to `Raw`.
#[derive(Debug, Deserialize, Default)]
struct CheckRequest {
    #[serde(alias = "tool")]
    tool_name: String,
    #[serde(alias = "input")]
    parameters: serde_json::Value,
    #[serde(default)]
    metadata: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    client_kind: Option<String>,
}

/// Response for POST /api/v1/check.
#[derive(Debug, Serialize)]
struct CheckResponse {
    permission: String,
    action_type: String,
    channel: String,
    norm_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_reason: Option<String>,
    source: String,
}

/// POST /api/v1/check handler.
async fn check_handler(
    State(state): State<ServerState>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    // Pull well-known fields out of metadata before moving it into the
    // tool_call. Anything else stays in metadata for normalizers/risk
    // rules to inspect.
    let session_id = extract_string_field(&req.metadata, "session_id");
    let task_goal = extract_string_field(&req.metadata, "task_goal");

    // Resolve client_kind. Default is Raw (passthrough) — clients that
    // already pass bare tool names work without sending the field.
    // Unknown values silently fall back to Raw rather than 400-ing, since
    // a strict deserializer on a host hint creates a deployment coupling
    // we'd rather not enforce at the wire boundary.
    let client_kind = req
        .client_kind
        .as_deref()
        .and_then(|s| ClientKind::from_str(s).ok())
        .unwrap_or(ClientKind::Raw);

    // Strip host-specific tool-name prefix so YAML normalizers can match
    // the bare name. Mirrors the stdin-hook adapter (see hook.rs).
    let stripped_tool_name = client_kind.strip_prefix(&req.tool_name).to_string();

    let tool_call = RawToolCall {
        tool_name: stripped_tool_name,
        parameters: req.parameters,
        metadata: req.metadata,
    };

    let mut ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&state.org_domain))
        .with_skip_audit(state.calibrate);
    if let Some(sid) = session_id {
        ctx = ctx.with_session(SessionContext::new(sid));
    }
    if let Some(goal) = task_goal {
        ctx = ctx.with_task_goal(goal);
    }

    let result = state.engine.get_permission(&tool_call, &ctx).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("engine error: {e}"),
        )
    })?;

    let (result, meta) = apply_calibration(&state, result).await?;

    let surface_command = tool_call
        .parameters
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    let surface_tool = tool_call.tool_name.clone();
    record_and_respond(
        &state,
        &result,
        &tool_call,
        &ctx,
        surface_tool,
        surface_command,
        meta,
    )
}



/// Pull a string field out of the metadata map, ignoring non-string types.
fn extract_string_field(
    metadata: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    metadata
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

// ── Audit replay (Lane A step 1b) ─────────────────────────────────────

/// One buffered failed-open event from a client. Mirrors
/// `FailedOpenEvent` in @permit0/openclaw's TS code.
#[derive(Debug, Deserialize)]
struct FailedOpenEvent {
    event_id: String,
    #[allow(dead_code)] // captured for forensics, not consumed server-side today
    occurred_at: String,
    tool_name: String,
    parameters: serde_json::Value,
    #[serde(default)]
    metadata: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    fail_reason: String,
    #[serde(default)]
    fail_reason_code: String,
    #[allow(dead_code)] // captured for forensics, not consumed server-side today
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    client_version: String,
    #[serde(default)]
    fail_open_source: String,
}

/// Request body for POST /api/v1/audit/replay.
#[derive(Debug, Deserialize)]
struct ReplayRequest {
    events: Vec<FailedOpenEvent>,
    #[serde(default)]
    client_window_start: String,
    #[serde(default)]
    client_window_end: String,
    #[serde(default)]
    #[allow(dead_code)] // surfaced in dashboard banner (Lane A step 1c), not in this response
    dropped_count: u32,
}

/// One per-event failure inside a partial replay batch.
#[derive(Debug, Serialize)]
struct ReplayRejection {
    event_id: String,
    error: String,
}

/// Response body for POST /api/v1/audit/replay.
#[derive(Debug, Serialize)]
struct ReplayResponse {
    accepted: u32,
    rejected: Vec<ReplayRejection>,
}

/// Maximum events accepted in a single replay batch. The TS client batches
/// at 100; 500 leaves headroom for client retries that bundle multiple
/// drained windows.
const REPLAY_BATCH_MAX: usize = 500;

/// POST /api/v1/audit/replay handler.
///
/// Accepts a batch of `FailedOpenEvent`s buffered by a client during a
/// daemon outage. For each event, retro-scores against the current pack
/// to compute the would-have decision, then writes one audit entry with
/// `decision_source: "failed_open"` and the retroactive verdict.
///
/// v1 limitations (called out so future tightening is informed):
///   - No idempotency dedup. The TS client uses ULIDs and a single-flight
///     drain mutex, so duplicates are rare. Auditors can dedupe by
///     `event_id` (visible in raw_tool_call.metadata) at query time.
///   - No summary entry per batch. The dashboard banner (Lane A 1c) reads
///     directly from the audit log, grouping by client_window_start/end.
async fn audit_replay_handler(
    State(state): State<ServerState>,
    Json(req): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, (StatusCode, String)> {
    if req.events.len() > REPLAY_BATCH_MAX {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "replay batch too large: {} events (max {})",
                req.events.len(),
                REPLAY_BATCH_MAX
            ),
        ));
    }

    let mut accepted: u32 = 0;
    let mut rejected: Vec<ReplayRejection> = Vec::new();

    for event in &req.events {
        let session_id = extract_string_field(&event.metadata, "session_id");
        let task_goal = extract_string_field(&event.metadata, "task_goal");

        let mut metadata = event.metadata.clone();
        // Stamp event_id into metadata so it survives the audit redactor
        // and surfaces in raw_tool_call.metadata.event_id for dedup queries.
        metadata.insert(
            "event_id".to_string(),
            serde_json::Value::String(event.event_id.clone()),
        );

        let tool_call = RawToolCall {
            tool_name: event.tool_name.clone(),
            parameters: event.parameters.clone(),
            metadata,
        };

        let mut ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&state.org_domain))
            .with_skip_audit(true); // we'll write our own failed-open entry below
        if let Some(sid) = session_id {
            ctx = ctx.with_session(SessionContext::new(sid));
        }
        if let Some(goal) = task_goal {
            ctx = ctx.with_task_goal(goal);
        }

        let result = match state.engine.get_permission(&tool_call, &ctx) {
            Ok(r) => r,
            Err(e) => {
                rejected.push(ReplayRejection {
                    event_id: event.event_id.clone(),
                    error: format!("retro-score failed: {e}"),
                });
                continue;
            }
        };

        let foc = FailedOpenContext {
            fail_reason_code: event.fail_reason_code.clone(),
            fail_reason: event.fail_reason.clone(),
            client_window_start: req.client_window_start.clone(),
            client_window_end: req.client_window_end.clone(),
            client_version: event.client_version.clone(),
            fail_open_source: event.fail_open_source.clone(),
        };

        match state
            .engine
            .log_failed_open_replay(&tool_call, &ctx, &result, foc)
        {
            Ok(_entry_id) => accepted += 1,
            Err(e) => rejected.push(ReplayRejection {
                event_id: event.event_id.clone(),
                error: format!("audit write failed: {e}"),
            }),
        }
    }

    Ok(Json(ReplayResponse { accepted, rejected }))
}

/// Request body for POST /api/v1/check_action.
#[derive(Debug, Deserialize)]
struct CheckActionRequest {
    action_type: String,
    #[serde(default = "default_channel")]
    channel: String,
    #[serde(default)]
    entities: Entities,
}

fn default_channel() -> String {
    "app".to_string()
}

/// POST /api/v1/check_action handler — evaluate a pre-normalized action.
///
/// Used by language SDKs (e.g. `@permit0.guard("email.send")` in Python)
/// where the caller already knows the norm action and doesn't need
/// YAML normalizer translation.
async fn check_action_handler(
    State(state): State<ServerState>,
    Json(req): Json<CheckActionRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let action_type = ActionType::parse(&req.action_type)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid action_type: {e}")))?;

    let surface_tool = format!("__action:{}", req.action_type);
    let norm = NormAction {
        action_type,
        channel: req.channel,
        entities: req.entities.clone(),
        execution: ExecutionMeta {
            surface_tool: surface_tool.clone(),
            surface_command: String::new(),
        },
    };

    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&state.org_domain))
        .with_skip_audit(state.calibrate);

    // Synthesize a raw tool call mirroring what `check_norm_action` does
    // internally, so the audit chain has something to record on calibration.
    let synthetic_tool_call = RawToolCall {
        tool_name: surface_tool.clone(),
        parameters: serde_json::Value::Object(req.entities),
        metadata: Default::default(),
    };

    let result = state.engine.check_norm_action(norm, &ctx).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("engine error: {e}"),
        )
    })?;

    let (result, meta) = apply_calibration(&state, result).await?;

    record_and_respond(
        &state,
        &result,
        &synthetic_tool_call,
        &ctx,
        surface_tool,
        String::new(),
        meta,
    )
}

/// In calibration mode, escalate every fresh decision (engine-produced —
/// not from list/cache or a previous human review) to a human-in-the-loop
/// approval. The HTTP request blocks until the human submits a decision
/// via the dashboard, or until the approval timeout expires.
///
/// Cache is updated with the human's decision so subsequent identical calls
/// reflect the calibrated answer.
async fn apply_calibration(
    state: &ServerState,
    result: PermissionResult,
) -> Result<(PermissionResult, CalibrationMeta), (StatusCode, String)> {
    if !state.calibrate {
        return Ok((result, CalibrationMeta::default()));
    }
    // Skip when the decision came from a place where the human already had
    // a say (allowlist/denylist/HumanReviewer) or we're replaying a previous
    // decision (PolicyCache).
    match result.source {
        DecisionSource::Allowlist
        | DecisionSource::Denylist
        | DecisionSource::PolicyCache
        | DecisionSource::HumanReviewer => return Ok((result, CalibrationMeta::default())),
        // Scorer / AgentReviewer / UnknownFallback — permit0 has no
        // recorded human decision yet, so calibration mode should park
        // the call for human review. UnknownFallback is especially
        // important to surface: there's no risk rule, so the human's
        // verdict is the only signal we'll get.
        DecisionSource::Scorer
        | DecisionSource::AgentReviewer
        | DecisionSource::UnknownFallback => {}
    }

    let manager = match &state.approval_manager {
        Some(m) => m.clone(),
        None => return Ok((result, CalibrationMeta::default())),
    };

    // Construct a RiskScore for the dashboard display (synthesize a Minimal
    // entry if the engine didn't produce one — rare, but possible).
    let risk_score = result.risk_score.clone().unwrap_or_else(|| RiskScore {
        raw: 0.0,
        score: 0,
        tier: Tier::Minimal,
        blocked: false,
        flags: Vec::new(),
        block_reason: None,
        reason: "no risk score (cache or fast-path)".into(),
    });

    let original_permission = result.permission;
    let norm_hash = result.norm_action.norm_hash();

    let (approval_id, rx) = manager.create_pending(result.norm_action.clone(), risk_score);
    let timeout = manager.timeout();

    eprintln!(
        "[calibrate] awaiting human decision for {} ({}) — engine says {:?}, approval_id={}",
        result.norm_action.action_type.as_action_str(),
        result.norm_action.channel,
        original_permission,
        approval_id,
    );

    // Block until the human decides or the approval times out.
    let decision = match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(d)) => d,
        Ok(Err(_)) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "approval channel closed unexpectedly".into(),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                format!(
                    "calibration timeout after {}s; no human decision",
                    timeout.as_secs()
                ),
            ));
        }
    };

    eprintln!(
        "[calibrate] human → {:?} (engine had → {:?}) reviewer={} reason={}",
        decision.permission, original_permission, decision.reviewer, decision.reason,
    );

    // Persist the human's decision in the cache so future identical calls
    // reflect the calibrated answer (overwriting the engine's recommendation).
    let _ = state
        .engine
        .store()
        .policy_cache_set(norm_hash, decision.permission);

    let meta = CalibrationMeta {
        engine_permission: Some(original_permission),
        reviewer: Some(decision.reviewer),
        reason: Some(decision.reason),
    };
    let new_result = PermissionResult {
        permission: decision.permission,
        norm_action: result.norm_action,
        risk_score: result.risk_score,
        source: DecisionSource::HumanReviewer,
    };
    Ok((new_result, meta))
}

/// Calibration metadata attached to a decision when a human reviewer
/// approved/denied. None for non-calibration calls.
#[derive(Default)]
struct CalibrationMeta {
    engine_permission: Option<permit0_types::Permission>,
    reviewer: Option<String>,
    reason: Option<String>,
}

/// Persist the decision (if a shared store is configured) and serialize the response.
fn record_and_respond(
    state: &ServerState,
    result: &permit0_engine::PermissionResult,
    tool_call: &RawToolCall,
    ctx: &PermissionCtx,
    surface_tool: String,
    surface_command: String,
    calibration: CalibrationMeta,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    if let Some(ref store) = state.store {
        let record = DecisionRecord {
            id: ulid::Ulid::new().to_string(),
            norm_hash: result.norm_action.norm_hash(),
            action_type: result.norm_action.action_type.as_action_str().to_string(),
            channel: result.norm_action.channel.clone(),
            permission: result.permission,
            source: format!("{:?}", result.source),
            tier: result.risk_score.as_ref().map(|s| s.tier),
            risk_raw: result.risk_score.as_ref().map(|s| s.raw),
            blocked: result.risk_score.as_ref().is_some_and(|s| s.blocked),
            flags: result
                .risk_score
                .as_ref()
                .map_or_else(Vec::new, |s| s.flags.clone()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            surface_tool,
            surface_command,
            engine_permission: calibration.engine_permission,
            reviewer: calibration.reviewer.clone(),
            reason: calibration.reason.clone(),
        };
        let _ = store.save_decision(record);
    }

    // When a human calibrated this decision, the engine's normal audit
    // write was suppressed via `ctx.skip_audit`. Append the composite
    // entry now so the dashboard's audit log and recent-decisions list
    // see it. `engine_permission` is the pre-calibration verdict — the
    // chain stores it in `engine_decision` so the dashboard can show
    // override information ("permit0 said vs human said vs match?").
    if let (Some(engine_permission), Some(reviewer), Some(reason)) = (
        calibration.engine_permission,
        calibration.reviewer,
        calibration.reason,
    ) {
        if let Err(e) = state.engine.log_calibrated_audit(
            result,
            tool_call,
            ctx,
            engine_permission,
            reviewer,
            reason,
        ) {
            tracing::warn!("failed to append calibrated audit entry: {e}");
        }
    }

    Ok(Json(CheckResponse {
        permission: result.permission.to_string().to_lowercase(),
        action_type: result.norm_action.action_type.as_action_str().to_string(),
        channel: result.norm_action.channel.clone(),
        norm_hash: result.norm_action.norm_hash_hex(),
        score: result.risk_score.as_ref().map(|s| s.score),
        tier: result.risk_score.as_ref().map(|s| s.tier.to_string()),
        blocked: result.risk_score.as_ref().map(|s| s.blocked),
        block_reason: result
            .risk_score
            .as_ref()
            .and_then(|s| s.block_reason.clone()),
        source: format!("{:?}", result.source),
    }))
}

/// GET /api/v1/health handler.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "permit0" }))
}

/// Run the HTTP server.
pub fn run(
    port: u16,
    profile: Option<String>,
    org_domain: &str,
    with_ui: bool,
    calibrate: bool,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(async move {
        let app = if with_ui {
            // Shared in-memory audit sink so /check and /audit/replay both
            // write here, and the dashboard can read the same chain. This
            // is what makes failed-open windows visible to the banner UI.
            //
            // For now the sink is in-memory only — it is wiped on daemon
            // restart. Persisting the audit chain to disk is a separate
            // hardening step (the SQLite store at db_path is for
            // DecisionRecords only; chained AuditEntries need their own
            // sink implementation that writes to disk).
            let audit_sink: Arc<dyn AuditSink> = Arc::new(InMemoryAuditSink::new());
            let audit_signer: Arc<dyn AuditSigner> = Arc::new(Ed25519Signer::generate());

            let engine = engine_factory::build_engine_builder_from_packs(profile.as_deref(), None)?
                .with_audit(audit_sink.clone(), audit_signer)
                .build()?;

            let packs_dir = engine_factory::resolve_packs_dir(None);
            let db_dir = engine_factory::dirs_home()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".permit0");
            std::fs::create_dir_all(&db_dir).ok();
            let db_path = db_dir.join("permit0.db");
            eprintln!("  database at {}", db_path.display());
            let shared_store: Arc<dyn Store> = match SqliteStore::open(&db_path) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    eprintln!(
                        "  warning: failed to open SQLite store ({e}), falling back to in-memory"
                    );
                    Arc::new(InMemoryStore::new())
                }
            };

            // Shared approval manager so the daemon's calibration handler and
            // the dashboard's /api/v1/approvals/decide endpoint resolve the
            // same oneshot channels.
            let approval_manager = Arc::new(ApprovalManager::new());

            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
                store: Some(shared_store.clone()),
                calibrate,
                approval_manager: Some(approval_manager.clone()),
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
                .route("/check_action", post(check_action_handler))
                .route("/audit/replay", post(audit_replay_handler))
                .with_state(server_state);

            let ui_state = AppState {
                store: shared_store,
                audit_sink: Some(audit_sink),
                token_store: Arc::new(TokenStore::new()),
                approval_manager,
                packs_dir: packs_dir.clone(),
                profiles_dir: Some(std::path::PathBuf::from("profiles")),
            };
            let ui_router = permit0_ui::build_router(ui_state);

            let mut app = Router::new().nest("/api/v1", check_api).merge(ui_router);

            let cwd_static = std::path::Path::new("crates/permit0-ui/static");
            if cwd_static.exists() {
                app = app.nest_service("/ui", ServeDir::new(cwd_static));
            }

            app
        } else {
            // No-UI mode: no shared audit sink. Calls still work but
            // failed-open replay events have nowhere to land in the
            // audit chain. The /audit/replay endpoint will accept the
            // batch and the engine's log_failed_open_replay will no-op
            // when no AuditSink is configured.
            let engine = engine_factory::build_engine_from_packs(profile.as_deref(), None)?;
            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
                store: None,
                calibrate: false,
                approval_manager: None,
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
                .route("/check_action", post(check_action_handler))
                .route("/audit/replay", post(audit_replay_handler))
                .route("/health", get(health))
                .with_state(server_state);
            Router::new().nest("/api/v1", check_api)
        };

        let addr = format!("0.0.0.0:{port}");
        eprintln!("permit0 server listening on {addr}");
        if with_ui {
            eprintln!("  API mounted at /api/v1/");
            eprintln!("  admin dashboard at http://0.0.0.0:{port}/ui/");
        }

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .context("binding listener")?;
        axum::serve(listener, app).await.context("running server")?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_response_serialization() {
        let resp = CheckResponse {
            permission: "allow".into(),
            action_type: "system.exec".into(),
            channel: "bash".into(),
            norm_hash: "abc123".into(),
            score: Some(12),
            tier: Some("Minimal".into()),
            blocked: Some(false),
            block_reason: None,
            source: "Scoring".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""permission":"allow""#));
        assert!(!json.contains("block_reason"));
    }

    #[test]
    fn check_request_deserialization() {
        let json = r#"{"tool": "Bash", "input": {"command": "ls"}}"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tool_name, "Bash");
        assert_eq!(req.parameters["command"], "ls");
        // metadata defaults to empty when absent
        assert!(req.metadata.is_empty());
    }

    #[test]
    fn check_request_accepts_metadata() {
        let json = r#"{
            "tool_name": "Bash",
            "parameters": {"command": "ls"},
            "metadata": {
                "session_id": "conv-42",
                "task_goal": "list files",
                "trace_id": "abc-123"
            }
        }"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.metadata.get("session_id").unwrap(), "conv-42");
        assert_eq!(req.metadata.get("task_goal").unwrap(), "list files");
        assert_eq!(req.metadata.get("trace_id").unwrap(), "abc-123");
    }

    #[test]
    fn check_request_accepts_client_kind() {
        let json = r#"{
            "tool_name": "gmail.create_label",
            "parameters": {},
            "client_kind": "openclaw"
        }"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.client_kind.as_deref(), Some("openclaw"));
    }

    #[test]
    fn check_request_client_kind_defaults_to_none() {
        let json = r#"{"tool_name": "Bash", "parameters": {}}"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert!(req.client_kind.is_none());
    }

    #[test]
    fn extract_string_field_pulls_strings() {
        let mut m = serde_json::Map::new();
        m.insert("session_id".into(), serde_json::json!("s-1"));
        m.insert("task_goal".into(), serde_json::json!("do thing"));
        assert_eq!(extract_string_field(&m, "session_id"), Some("s-1".into()));
        assert_eq!(
            extract_string_field(&m, "task_goal"),
            Some("do thing".into())
        );
    }

    #[test]
    fn extract_string_field_returns_none_for_missing() {
        let m = serde_json::Map::new();
        assert_eq!(extract_string_field(&m, "session_id"), None);
    }

    #[test]
    fn extract_string_field_returns_none_for_non_string() {
        let mut m = serde_json::Map::new();
        m.insert("session_id".into(), serde_json::json!(42));
        m.insert("task_goal".into(), serde_json::json!({"nested": "object"}));
        // Non-string types are ignored rather than coerced — silently
        // dropping a malformed field is safer than guessing what the
        // caller meant. The TS client only ever sends strings.
        assert_eq!(extract_string_field(&m, "session_id"), None);
        assert_eq!(extract_string_field(&m, "task_goal"), None);
    }

    #[test]
    fn extract_string_field_returns_none_for_empty_string() {
        let mut m = serde_json::Map::new();
        m.insert("session_id".into(), serde_json::json!(""));
        // Empty string is treated as absent so we don't write empty
        // session_ids into the audit log.
        assert_eq!(extract_string_field(&m, "session_id"), None);
    }

    // ── Audit replay deserialization (Lane A step 1b) ────────────────

    #[test]
    fn replay_request_minimal_shape() {
        // The TS client always sends the full set of fields; minimal shape
        // here verifies serde defaults work so a partial migration of the
        // client doesn't break the endpoint.
        let json = r#"{
            "events": [
                {
                    "event_id": "01JX",
                    "occurred_at": "2026-04-30T10:00:00Z",
                    "tool_name": "Bash",
                    "parameters": {"command": "ls"}
                }
            ]
        }"#;
        let req: ReplayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.events.len(), 1);
        assert_eq!(req.events[0].event_id, "01JX");
        assert_eq!(req.events[0].tool_name, "Bash");
        assert_eq!(req.dropped_count, 0);
        assert_eq!(req.client_window_start, "");
    }

    #[test]
    fn replay_request_full_shape() {
        let json = r#"{
            "events": [
                {
                    "event_id": "01JX",
                    "occurred_at": "2026-04-30T10:00:00Z",
                    "tool_name": "Bash",
                    "parameters": {"command": "ls"},
                    "metadata": {"session_id": "conv-1", "trace_id": "t1"},
                    "fail_reason": "ECONNREFUSED",
                    "fail_reason_code": "refused",
                    "outcome": "executed",
                    "client_version": "0.1.0",
                    "fail_open_source": "env_var"
                }
            ],
            "client_window_start": "2026-04-30T10:00:00Z",
            "client_window_end":   "2026-04-30T10:05:00Z",
            "dropped_count": 7
        }"#;
        let req: ReplayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.events[0].fail_reason_code, "refused");
        assert_eq!(req.events[0].fail_open_source, "env_var");
        assert_eq!(req.events[0].metadata.get("session_id").unwrap(), "conv-1");
        assert_eq!(req.client_window_start, "2026-04-30T10:00:00Z");
        assert_eq!(req.dropped_count, 7);
    }

    #[test]
    fn replay_response_serialization() {
        let resp = ReplayResponse {
            accepted: 12,
            rejected: vec![ReplayRejection {
                event_id: "01JX-bad".into(),
                error: "audit write failed".into(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""accepted":12"#));
        assert!(json.contains(r#""event_id":"01JX-bad""#));
    }
}
