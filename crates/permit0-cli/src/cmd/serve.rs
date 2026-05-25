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
use permit0_store::audit::{AuditSigner, AuditSink, FailedOpenContext, FileKeyStore};
use permit0_store::{InMemoryPolicyState, PolicyState, SqliteAuditSink, SqlitePolicyState};
use permit0_types::{
    ActionType, ExecutionMeta, NormAction, Parameters, RawToolCall, RiskScore, Tier,
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
    /// HITL routing mode. `"ui-wait"` blocks this handler until a human
    /// resolves the call in the dashboard; absent / `"cc-prompt"` keeps
    /// today's behavior (verdict returned immediately).
    #[serde(default)]
    hitl_routing: Option<String>,
    /// `ui-wait` block timeout in seconds. On expiry the handler returns
    /// `permission: "deny"` with an "approval timed out" reason.
    #[serde(default)]
    hitl_timeout_secs: Option<u64>,
    /// Override for the daemon's `--org-domain` on a per-request basis.
    /// Lets a hook configured via `~/.permit0/config.yaml` control
    /// internal/external recipient classification without reconfiguring
    /// the daemon. Falls back to `state.org_domain` when absent.
    #[serde(default)]
    org_domain: Option<String>,
}

/// Response for POST /api/v1/check.
#[derive(Debug, Serialize)]
struct CheckResponse {
    permission: String,
    action_type: String,
    source: String,
    norm_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_reason: Option<String>,
    decision_source: String,
}

/// Should this request be routed through the `ui-wait` blocking path?
/// Returns true only when the field is explicitly `"ui-wait"` (or its
/// underscore variant). Treats absent / empty / `"cc-prompt"` as the
/// today-default behavior.
fn should_dispatch_ui_wait(field: Option<&str>) -> bool {
    matches!(field, Some("ui-wait") | Some("ui_wait"))
}

/// Does this engine verdict warrant blocking on the ui-wait approval
/// dashboard? Only HumanInTheLoop verdicts produced by actual risk
/// scoring qualify — `UnknownFallback` HITL is the engine saying "I
/// have no opinion", and the hook's `--unknown` policy is what the
/// operator configured to handle that case. Intercepting here would
/// override their bypass and defeat the whole point of `--unknown`.
fn verdict_qualifies_for_ui_wait(
    permission: permit0_types::Permission,
    source: DecisionSource,
) -> bool {
    matches!(permission, permit0_types::Permission::HumanInTheLoop)
        && source != DecisionSource::UnknownFallback
}

/// POST /api/v1/check handler.
async fn check_handler(
    State(state): State<ServerState>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let session_id = extract_string_field(&req.metadata, "session_id");
    let task_goal = extract_string_field(&req.metadata, "task_goal");

    let client_kind = req
        .client_kind
        .as_deref()
        .and_then(|s| ClientKind::from_str(s).ok())
        .unwrap_or(ClientKind::Raw);
    let stripped_tool_name = client_kind.strip_prefix(&req.tool_name).to_string();

    // Pull routing knobs out before moving the rest into `tool_call`.
    let want_ui_wait = should_dispatch_ui_wait(req.hitl_routing.as_deref());
    let ui_wait_timeout = std::time::Duration::from_secs(req.hitl_timeout_secs.unwrap_or(300));
    // Hook-supplied org_domain wins; fall back to the daemon's own.
    let effective_org_domain = req
        .org_domain
        .as_deref()
        .unwrap_or(state.org_domain.as_str())
        .to_string();

    let tool_call = RawToolCall {
        tool_name: stripped_tool_name,
        parameters: req.parameters,
        metadata: req.metadata,
    };

    // ui-wait requested but the daemon was started without --ui: fail
    // loud so the operator sees the misconfiguration rather than a
    // silent fallback.
    if want_ui_wait && state.approval_manager.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "ui-wait routing not supported by this daemon (start with --ui)".to_string(),
        ));
    }

    let mut ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(&effective_org_domain))
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

    // ui-wait dispatch: only when the verdict is genuinely HITL AND the
    // engine actually scored the action. See `verdict_qualifies_for_ui_wait`.
    let result = if want_ui_wait && verdict_qualifies_for_ui_wait(result.permission, result.source)
    {
        let manager = state
            .approval_manager
            .as_ref()
            .expect("checked above")
            .clone();
        await_ui_wait_approval(
            manager,
            state.engine.state(),
            result.norm_action,
            result.risk_score,
            ui_wait_timeout,
        )
        .await?
    } else {
        result
    };

    let (result, meta) = apply_calibration(&state, result).await?;

    record_and_respond(&state, &result, &tool_call, &ctx, meta).await
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
            .await
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
    #[serde(default = "default_source")]
    source: String,
    #[serde(default)]
    parameters: Parameters,
}

fn default_source() -> String {
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
        source: req.source,
        parameters: req.parameters.clone(),
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
        tool_name: surface_tool,
        parameters: serde_json::Value::Object(req.parameters),
        metadata: Default::default(),
    };

    let result = state.engine.check_norm_action(norm, &ctx).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("engine error: {e}"),
        )
    })?;

    let (result, meta) = apply_calibration(&state, result).await?;

    record_and_respond(&state, &result, &synthetic_tool_call, &ctx, meta).await
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
        | DecisionSource::HumanReviewer
        | DecisionSource::HumanApproval => return Ok((result, CalibrationMeta::default())),
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
    let original_source = result.source;
    let norm_hash = result.norm_action.norm_hash();

    let (approval_id, rx) = manager.create_pending(result.norm_action.clone(), risk_score);
    let timeout = manager.timeout();

    eprintln!(
        "[calibrate] awaiting human decision for {} ({}) — engine says {:?}, approval_id={}",
        result.norm_action.action_type.as_action_str(),
        result.norm_action.source,
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
    //
    // Two skip rules:
    //  1. Per spec §4.2 step 4(i), HumanInTheLoop verdicts pin the call
    //     and re-park the operator on every retry — never cache them.
    //  2. UnknownFallback-origin actions are "permit0 has no opinion";
    //     a one-time human "allow" must not promote to a permanent
    //     bypass for the same `norm_hash`. Each unknown call should
    //     surface afresh so operators can decide each time (or write a
    //     pack to make it `Scorer`-tier).
    let should_cache = decision.permission != permit0_types::Permission::HumanInTheLoop
        && original_source != DecisionSource::UnknownFallback;
    if should_cache {
        let _ = state
            .engine
            .state()
            .policy_cache_set(norm_hash, decision.permission, None)
            .await;
    }

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

/// Block the current request until a human resolves the call via the
/// dashboard, then return a `PermissionResult` with the resolved verdict
/// and `DecisionSource::HumanApproval`. On timeout, returns a `Deny`
/// result with an "approval timed out" block reason and persists the
/// auto-deny via `approval_resolve` so the queue stays consistent.
///
/// Caller invariant: only call this when the original engine verdict
/// was `HumanInTheLoop` AND `req.hitl_routing == Some("ui-wait")`.
/// Other paths must bypass this helper so cc-prompt callers and
/// cached / fast-path verdicts are not double-blocked.
pub(crate) async fn await_ui_wait_approval(
    manager: std::sync::Arc<permit0_ui::ApprovalManager>,
    policy_state: &dyn permit0_store::PolicyState,
    norm_action: permit0_types::NormAction,
    risk_score: Option<permit0_types::RiskScore>,
    timeout: std::time::Duration,
) -> Result<permit0_engine::PermissionResult, (axum::http::StatusCode, String)> {
    use permit0_engine::{DecisionSource, PermissionResult};
    use permit0_store::{HumanDecisionRow, PendingApprovalRow};
    use permit0_types::{Permission, RiskScore, Tier};

    let synthesized_score = risk_score.clone().unwrap_or_else(|| RiskScore {
        raw: 0.0,
        score: 0,
        tier: Tier::Medium,
        blocked: false,
        flags: vec![],
        block_reason: None,
        reason: "no risk score (ui-wait synthesized)".into(),
    });

    let (approval_id, rx) = manager.create_pending(norm_action.clone(), synthesized_score.clone());
    let norm_hash = norm_action.norm_hash();
    let created_at = chrono::Utc::now().to_rfc3339();

    // Best-effort durable persistence. Failures here are logged but do
    // not abort the wait — the in-process channel still works and the
    // hook still gets its verdict. Operators with multi-process
    // requirements should monitor this log line.
    let pending_row = PendingApprovalRow {
        approval_id: approval_id.clone(),
        norm_hash,
        action_type: norm_action.action_type.as_action_str().to_string(),
        source: norm_action.source.clone(),
        created_at: created_at.clone(),
        norm_action_json: serde_json::to_string(&norm_action).unwrap_or_default(),
        risk_score_json: serde_json::to_string(&synthesized_score).unwrap_or_default(),
    };
    if let Err(e) = policy_state.approval_create(pending_row).await {
        tracing::warn!("ui-wait: approval_create failed (in-memory only): {e}");
    }

    // Block until the human decides or the configured timeout fires.
    let timeout_outcome = tokio::time::timeout(timeout, rx).await;

    match timeout_outcome {
        Ok(Ok(decision)) => {
            // Persist the resolution and update the cache so the next
            // identical call hits the cache instead of re-prompting.
            // Per spec §4.2 step 4(i), do NOT cache HumanInTheLoop verdicts —
            // that would pin the call and re-park the operator on every retry.
            if decision.permission != Permission::HumanInTheLoop {
                let _ = policy_state
                    .policy_cache_set(norm_hash, decision.permission, risk_score.clone())
                    .await;
            }
            let _ = policy_state
                .approval_resolve(
                    &approval_id,
                    HumanDecisionRow {
                        permission: decision.permission,
                        reason: decision.reason.clone(),
                        reviewer: decision.reviewer.clone(),
                        decided_at: chrono::Utc::now().to_rfc3339(),
                    },
                )
                .await;
            Ok(PermissionResult {
                permission: decision.permission,
                norm_action,
                risk_score,
                source: DecisionSource::HumanApproval,
            })
        }
        Ok(Err(_recv_err)) => {
            // Sender dropped without a decision (shouldn't happen unless
            // the manager was reset). Fail safe to Deny.
            let block_reason = "approval channel closed unexpectedly".to_string();
            let scored = risk_score.map(|mut s| {
                s.block_reason = Some(block_reason.clone());
                s
            });
            Ok(PermissionResult {
                permission: Permission::Deny,
                norm_action,
                risk_score: scored,
                source: DecisionSource::HumanApproval,
            })
        }
        Err(_elapsed) => {
            let block_reason = format!("approval timed out after {}s", timeout.as_secs());
            // Persist an auto-deny resolution so the dashboard's queue
            // doesn't show the row forever.
            let _ = policy_state
                .approval_resolve(
                    &approval_id,
                    HumanDecisionRow {
                        permission: Permission::Deny,
                        reason: block_reason.clone(),
                        reviewer: "<timeout>".into(),
                        decided_at: chrono::Utc::now().to_rfc3339(),
                    },
                )
                .await;
            let scored = risk_score
                .map(|mut s| {
                    s.block_reason = Some(block_reason.clone());
                    s
                })
                .or_else(|| {
                    Some(RiskScore {
                        raw: 0.0,
                        score: 0,
                        tier: Tier::Medium,
                        blocked: false,
                        flags: vec![],
                        block_reason: Some(block_reason),
                        reason: "ui-wait timeout".into(),
                    })
                });
            Ok(PermissionResult {
                permission: Permission::Deny,
                norm_action,
                risk_score: scored,
                source: DecisionSource::HumanApproval,
            })
        }
    }
}

/// Append the calibration audit entry (when applicable) and serialize the response.
///
/// The audit sink is the sole decision log. For ordinary requests the
/// engine has already written through the sink in its pipeline. For
/// calibrated requests the engine's normal audit write was suppressed
/// via `ctx.skip_audit`; this function appends the composite entry now
/// so the dashboard sees the human's verdict and `engine_decision`
/// preserves the pre-calibration recommendation for override visibility.
async fn record_and_respond(
    state: &ServerState,
    result: &permit0_engine::PermissionResult,
    tool_call: &RawToolCall,
    ctx: &PermissionCtx,
    calibration: CalibrationMeta,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    if let (Some(engine_permission), Some(reviewer), Some(reason)) = (
        calibration.engine_permission,
        calibration.reviewer,
        calibration.reason,
    ) {
        if let Err(e) = state
            .engine
            .log_calibrated_audit(result, tool_call, ctx, engine_permission, reviewer, reason)
            .await
        {
            tracing::warn!("failed to append calibrated audit entry: {e}");
        }
    }

    Ok(Json(CheckResponse {
        permission: result.permission.to_string().to_lowercase(),
        action_type: result.norm_action.action_type.as_action_str().to_string(),
        source: result.norm_action.source.clone(),
        norm_hash: result.norm_action.norm_hash_hex(),
        score: result.risk_score.as_ref().map(|s| s.score),
        tier: result.risk_score.as_ref().map(|s| s.tier.to_string()),
        blocked: result.risk_score.as_ref().map(|s| s.blocked),
        block_reason: result
            .risk_score
            .as_ref()
            .and_then(|s| s.block_reason.clone()),
        decision_source: format!("{:?}", result.source),
    }))
}

/// GET /api/v1/health handler.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "permit0" }))
}

/// Strip the password (and any `password=...` query parameter) from a
/// `postgres://user:password@host/db` URL before logging. Best-effort
/// redaction — anything we can't parse is logged as `<redacted>`.
fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            if u.password().is_some() {
                let _ = u.set_password(Some("***"));
            }
            u.to_string()
        }
        Err(_) => "<redacted>".to_string(),
    }
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
            let packs_dir = engine_factory::resolve_packs_dir(None);
            let db_dir = engine_factory::dirs_home()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".permit0");
            std::fs::create_dir_all(&db_dir).ok();

            // Connection-string env vars take precedence over the local
            // SQLite fallback. Two separate URLs so policy state and the
            // audit chain can live in distinct Postgres instances (the
            // `docker-compose.yml` shipped with the repo wires both).
            let state_url = std::env::var("PERMIT0_STATE_URL").ok();
            let audit_url = std::env::var("PERMIT0_AUDIT_URL").ok();

            let policy_state: Arc<dyn PolicyState> = match state_url.as_deref() {
                Some(url) => {
                    eprintln!("  state DB: postgres ({})", redact_url(url));
                    let pg = permit0_store::PostgresPolicyState::connect(url)
                        .await
                        .with_context(|| "connecting to state DB")?;
                    pg.migrate()
                        .await
                        .with_context(|| "running state DB migrations")?;
                    Arc::new(pg)
                }
                None => {
                    let state_db_path = db_dir.join("state.db");
                    eprintln!(
                        "  state DB: sqlite at {} (set PERMIT0_STATE_URL for Postgres)",
                        state_db_path.display()
                    );
                    match SqlitePolicyState::open(&state_db_path) {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            eprintln!(
                                "  warning: failed to open state DB ({e}), falling back to in-memory"
                            );
                            Arc::new(InMemoryPolicyState::new())
                        }
                    }
                }
            };

            // Build the *primary* audit sink first. We keep the
            // concrete `PostgresAuditSink` alongside its `dyn AuditSink`
            // erasure so the digest writer can build a sibling
            // `PostgresDigestStore` from the same connection pool
            // without serve.rs naming sqlx types directly.
            let pg_audit: Option<Arc<permit0_store::PostgresAuditSink>> =
                match audit_url.as_deref() {
                    Some(url) => {
                        eprintln!("  audit DB: postgres ({})", redact_url(url));
                        let pg = permit0_store::PostgresAuditSink::connect(url)
                            .await
                            .with_context(|| "connecting to audit DB")?;
                        pg.migrate()
                            .await
                            .with_context(|| "running audit DB migrations")?;
                        Some(Arc::new(pg))
                    }
                    None => None,
                };
            let primary_audit: Arc<dyn AuditSink> = if let Some(ref pg) = pg_audit {
                pg.clone()
            } else {
                let audit_db_path = db_dir.join("audit.db");
                eprintln!(
                    "  audit DB: sqlite at {} (set PERMIT0_AUDIT_URL for Postgres)",
                    audit_db_path.display()
                );
                match SqliteAuditSink::open(&audit_db_path) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        eprintln!(
                            "  warning: failed to open audit DB ({e}), falling back to in-memory"
                        );
                        Arc::new(permit0_store::InMemoryAuditSink::new())
                    }
                }
            };

            // Optionally tee every audit write to an OpenTelemetry
            // collector (typically forwarded to S3 / Datadog / Splunk).
            // The primary stays the source of truth for queries; OTel
            // failures are logged and never block the engine.
            let audit_sink: Arc<dyn AuditSink> =
                if let Ok(endpoint) = std::env::var("PERMIT0_OTLP_ENDPOINT") {
                    eprintln!("  audit OTLP drain: {endpoint}");
                    match permit0_store::OtelAuditSink::http(&endpoint, true) {
                        Ok(otel) => Arc::new(permit0_store::TeeAuditSink::new(
                            primary_audit.clone(),
                            Arc::new(otel),
                        )),
                        Err(e) => {
                            eprintln!(
                                "  warning: failed to build OTel sink ({e}); skipping drain"
                            );
                            primary_audit.clone()
                        }
                    }
                } else {
                    primary_audit.clone()
                };

            // Persistent ed25519 signing key — preserved across restarts so
            // signatures remain verifiable with the same public key. The
            // mount point is configurable so a Docker bind-mount can drop
            // the seed under /var/lib/permit0/audit_signing.key.
            let key_path = std::env::var("PERMIT0_AUDIT_KEY_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| db_dir.join("audit_signing.key"));
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let signer = FileKeyStore::load_or_generate(&key_path)
                .with_context(|| format!("loading audit signing key at {}", key_path.display()))?;
            let audit_signer: Arc<dyn AuditSigner> = Arc::new(signer);
            eprintln!("  audit signing pubkey: {}", audit_signer.public_key_hex());

            // Resume the audit chain across restarts: read the head of the
            // sink and seed the engine builder so the next entry's
            // `prev_hash` and `sequence` continue monotonically.
            let seed = audit_sink
                .tail()
                .await
                .with_context(|| "reading audit chain tail")?;
            let mut builder = engine_factory::build_engine_builder_from_packs(
                profile.as_deref(),
                None,
            )?
            .with_policy_state(policy_state.clone())
            .with_audit(audit_sink.clone(), audit_signer.clone());
            if let Some((seq, prev)) = seed {
                eprintln!("  audit chain resuming at sequence {seq}");
                builder = builder.with_audit_seed(seq, prev);
            }
            let engine = builder.build()?;
            engine
                .reconcile_policy_cache()
                .await
                .context("reconciling policy cache against config fingerprint")?;

            // CloudTrail-style batch digests. Opt in by setting
            // `PERMIT0_DIGEST_DIR` (the directory absorbs one signed
            // digest file per batch). The Postgres path also pins each
            // digest in the audit DB so the dashboard can list them
            // without rescanning the disk.
            if let Ok(dir) = std::env::var("PERMIT0_DIGEST_DIR") {
                let interval_secs = std::env::var("PERMIT0_DIGEST_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(300);
                let batch_max = std::env::var("PERMIT0_DIGEST_BATCH_MAX")
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1000);

                match permit0_store::FileDigestStore::new(&dir) {
                    Ok(file_store) => {
                        let mut stores: Vec<Arc<dyn permit0_store::DigestStore>> =
                            vec![Arc::new(file_store)];
                        if let Some(ref pg) = pg_audit {
                            stores.push(Arc::new(
                                permit0_store::PostgresDigestStore::from_pool(
                                    pg.pool().clone(),
                                ),
                            ));
                        }
                        let writer = permit0_store::DigestWriter::new(
                            primary_audit.clone(),
                            audit_signer.clone(),
                            stores,
                            std::time::Duration::from_secs(interval_secs),
                            batch_max,
                        );
                        writer.spawn();
                        eprintln!(
                            "  digest writer: dir={dir} interval={interval_secs}s batch_max={batch_max}"
                        );
                    }
                    Err(e) => eprintln!("  warning: digest dir {dir} unavailable ({e})"),
                }
            }

            // Shared approval manager so the daemon's calibration handler and
            // the dashboard's /api/v1/approvals/decide endpoint resolve the
            // same oneshot channels.
            let approval_manager = Arc::new(ApprovalManager::new());

            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
                calibrate,
                approval_manager: Some(approval_manager.clone()),
            };
            let check_api = Router::new()
                .route("/check", post(check_handler))
                .route("/check_action", post(check_action_handler))
                .route("/audit/replay", post(audit_replay_handler))
                .with_state(server_state);

            let ui_state = AppState {
                state: policy_state,
                audit_sink,
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
            engine
                .reconcile_policy_cache()
                .await
                .context("reconciling policy cache against config fingerprint")?;
            let server_state = ServerState {
                engine: Arc::new(engine),
                org_domain: org_domain.into(),
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
            source: "bash".into(),
            norm_hash: "abc123".into(),
            score: Some(12),
            tier: Some("Minimal".into()),
            blocked: Some(false),
            block_reason: None,
            decision_source: "Scoring".into(),
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

    #[test]
    fn check_request_accepts_hitl_routing_fields() {
        let json = r#"{
            "tool_name": "Bash",
            "parameters": {"command": "ls"},
            "hitl_routing": "ui-wait",
            "hitl_timeout_secs": 600
        }"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hitl_routing.as_deref(), Some("ui-wait"));
        assert_eq!(req.hitl_timeout_secs, Some(600));
    }

    #[test]
    fn check_request_hitl_fields_default_to_none() {
        let json = r#"{"tool_name": "Bash", "parameters": {}}"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert!(req.hitl_routing.is_none());
        assert!(req.hitl_timeout_secs.is_none());
        // org_domain is the same shape — also defaults to None so the
        // handler falls back to state.org_domain.
        assert!(req.org_domain.is_none());
    }

    #[test]
    fn check_request_accepts_org_domain_override() {
        // The hook posts this so `~/.permit0/config.yaml`'s `org_domain`
        // wins over the daemon's --org-domain for the request's
        // internal/external recipient classification.
        let json = r#"{
            "tool_name": "gmail_send",
            "parameters": {"to": "bob@permit0.com"},
            "org_domain": "permit0.com"
        }"#;
        let req: CheckRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.org_domain.as_deref(), Some("permit0.com"));
    }

    #[test]
    fn ui_wait_requested_returns_true_when_field_matches() {
        assert!(should_dispatch_ui_wait(Some("ui-wait")));
        assert!(should_dispatch_ui_wait(Some("ui_wait")));
    }

    #[test]
    fn verdict_qualifies_for_ui_wait_only_for_scored_hitl() {
        use permit0_types::Permission;
        // Real HITL — from the scorer or agent reviewer — IS the case
        // ui-wait was designed for.
        assert!(verdict_qualifies_for_ui_wait(
            Permission::HumanInTheLoop,
            DecisionSource::Scorer
        ));
        assert!(verdict_qualifies_for_ui_wait(
            Permission::HumanInTheLoop,
            DecisionSource::AgentReviewer
        ));
        // Unknown-fallback HITL is the engine saying "no opinion" — the
        // hook's `--unknown` policy handles it; ui-wait must NOT park
        // the operator with `unknown: bypass` set.
        assert!(!verdict_qualifies_for_ui_wait(
            Permission::HumanInTheLoop,
            DecisionSource::UnknownFallback
        ));
        // Non-HITL verdicts never park, regardless of source.
        assert!(!verdict_qualifies_for_ui_wait(
            Permission::Allow,
            DecisionSource::Scorer
        ));
        assert!(!verdict_qualifies_for_ui_wait(
            Permission::Deny,
            DecisionSource::Scorer
        ));
    }

    #[test]
    fn ui_wait_requested_returns_false_for_cc_prompt_or_absent() {
        assert!(!should_dispatch_ui_wait(None));
        assert!(!should_dispatch_ui_wait(Some("cc-prompt")));
        assert!(!should_dispatch_ui_wait(Some("")));
    }

    #[tokio::test]
    async fn await_ui_wait_approval_returns_human_decision() {
        use permit0_engine::DecisionSource;
        use permit0_store::{InMemoryPolicyState, PolicyState};
        use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission, RiskScore, Tier};
        use permit0_ui::{ApprovalManager, HumanDecision};
        use std::sync::Arc;

        let manager = Arc::new(ApprovalManager::new());
        let policy_state: Arc<dyn PolicyState> = Arc::new(InMemoryPolicyState::new());

        let norm = NormAction {
            action_type: ActionType::parse("email.send").unwrap(),
            source: "gmail".into(),
            parameters: serde_json::Map::new(),
            execution: ExecutionMeta {
                surface_tool: "test".into(),
                surface_command: "test".into(),
            },
        };
        let risk = RiskScore {
            raw: 0.55,
            score: 55,
            tier: Tier::High,
            blocked: false,
            flags: vec!["MUTATION".into()],
            block_reason: None,
            reason: "test".into(),
        };

        let manager_for_decider = manager.clone();
        let decider = tokio::spawn(async move {
            // Poll until the pending row appears, then submit.
            for _ in 0..50 {
                let pending = manager_for_decider.list_pending();
                if let Some(p) = pending.first() {
                    manager_for_decider.submit_decision(
                        &p.approval_id,
                        HumanDecision {
                            permission: Permission::Allow,
                            reason: "looks fine".into(),
                            reviewer: "alice".into(),
                        },
                    );
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("no pending approval appeared");
        });

        let result = await_ui_wait_approval(
            manager.clone(),
            policy_state.as_ref(),
            norm.clone(),
            Some(risk),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("approval should resolve");

        decider.await.unwrap();
        assert_eq!(result.permission, Permission::Allow);
        assert_eq!(result.source, DecisionSource::HumanApproval);
        // Cache was set so the next identical call hits the cache.
        let cached = policy_state
            .policy_cache_get(&norm.norm_hash(), 3600)
            .await
            .unwrap();
        assert!(cached.is_some(), "policy cache should be populated");
        assert_eq!(cached.unwrap().permission, Permission::Allow);
    }

    #[tokio::test]
    async fn await_ui_wait_approval_times_out_to_deny() {
        use permit0_engine::DecisionSource;
        use permit0_store::{InMemoryPolicyState, PolicyState};
        use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission, RiskScore, Tier};
        use permit0_ui::ApprovalManager;
        use std::sync::Arc;

        let manager = Arc::new(ApprovalManager::new());
        let policy_state: Arc<dyn PolicyState> = Arc::new(InMemoryPolicyState::new());
        let norm = NormAction {
            action_type: ActionType::parse("email.send").unwrap(),
            source: "gmail".into(),
            parameters: serde_json::Map::new(),
            execution: ExecutionMeta {
                surface_tool: "test".into(),
                surface_command: "test".into(),
            },
        };
        let risk = RiskScore {
            raw: 0.5,
            score: 50,
            tier: Tier::High,
            blocked: false,
            flags: vec![],
            block_reason: None,
            reason: "test".into(),
        };

        let result = await_ui_wait_approval(
            manager.clone(),
            policy_state.as_ref(),
            norm.clone(),
            Some(risk),
            std::time::Duration::from_millis(50),
        )
        .await
        .expect("timeout path should yield Ok with Deny");

        assert_eq!(result.permission, Permission::Deny);
        assert_eq!(result.source, DecisionSource::HumanApproval);
        assert!(
            result
                .risk_score
                .as_ref()
                .and_then(|s| s.block_reason.as_deref())
                .unwrap_or_default()
                .contains("approval timed out"),
        );
    }

    #[tokio::test]
    async fn await_ui_wait_approval_does_not_cache_hitl_verdict() {
        use permit0_store::{InMemoryPolicyState, PolicyState};
        use permit0_types::{ActionType, ExecutionMeta, NormAction, Permission, RiskScore, Tier};
        use permit0_ui::{ApprovalManager, HumanDecision};
        use std::sync::Arc;

        let manager = Arc::new(ApprovalManager::new());
        let policy_state: Arc<dyn PolicyState> = Arc::new(InMemoryPolicyState::new());

        let norm = NormAction {
            action_type: ActionType::parse("email.send").unwrap(),
            source: "gmail".into(),
            parameters: serde_json::Map::new(),
            execution: ExecutionMeta {
                surface_tool: "test".into(),
                surface_command: "test".into(),
            },
        };
        let risk = RiskScore {
            raw: 0.55,
            score: 55,
            tier: Tier::High,
            blocked: false,
            flags: vec![],
            block_reason: None,
            reason: "test".into(),
        };

        let manager_for_decider = manager.clone();
        let decider = tokio::spawn(async move {
            for _ in 0..50 {
                let pending = manager_for_decider.list_pending();
                if let Some(p) = pending.first() {
                    // Reviewer submits HITL — must NOT pin the cache.
                    manager_for_decider.submit_decision(
                        &p.approval_id,
                        HumanDecision {
                            permission: Permission::HumanInTheLoop,
                            reason: "needs more eyes".into(),
                            reviewer: "alice".into(),
                        },
                    );
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("no pending approval appeared");
        });

        let result = await_ui_wait_approval(
            manager.clone(),
            policy_state.as_ref(),
            norm.clone(),
            Some(risk),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("approval should resolve");

        decider.await.unwrap();
        assert_eq!(result.permission, Permission::HumanInTheLoop);

        // Cache must be empty — a HITL verdict shouldn't pin the cache.
        let cached = policy_state
            .policy_cache_get(&norm.norm_hash(), 3600)
            .await
            .unwrap();
        assert!(
            cached.is_none(),
            "HITL verdicts must not populate the policy cache (would re-park every call)",
        );
    }
}
