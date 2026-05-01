#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use permit0_agent::{AgentReviewer, ReviewInput, ReviewVerdict};
use permit0_dsl::normalizer::DslNormalizer;
use permit0_dsl::risk_executor::{execute_risk_rules_with_sets, execute_session_rules_with_sets};
use permit0_dsl::schema::risk_rule::RiskRuleDef;
use permit0_dsl::validate;
use permit0_normalize::{Normalizer, NormalizerRegistry};
use permit0_scoring::{ScoringConfig, compute_hybrid};
use permit0_session::{SessionContext, evaluate_session_block_rules, session_amplifier_score};
use permit0_store::audit::{
    AuditEntry, AuditPolicy, AuditSigner, AuditSink, FailedOpenContext, HumanReview, Redactor,
    chain::{GENESIS_HASH, compute_entry_hash},
};
use permit0_store::{InMemoryStore, Store};
use permit0_types::{DecisionRecord, NormAction, Permission, RawToolCall, RiskScore, Tier};

use crate::context::PermissionCtx;
use crate::error::EngineError;

/// The result of a permission decision.
#[derive(Debug)]
pub struct PermissionResult {
    /// The final decision.
    pub permission: Permission,
    /// The normalized action (for audit).
    pub norm_action: NormAction,
    /// Risk score (if scoring was performed).
    pub risk_score: Option<RiskScore>,
    /// How the decision was reached.
    pub source: DecisionSource,
}

/// How a permission decision was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    Denylist,
    Allowlist,
    PolicyCache,
    Scorer,
    /// LLM-based agent reviewer (when configured via
    /// `EngineBuilder::with_reviewer`) ran and produced a verdict on a
    /// Medium-tier action.
    AgentReviewer,
    /// A human approved/denied this action (typically via the dashboard
    /// in calibration mode, or the HITL approval flow). The audit record
    /// will also have a `reviewer` field set.
    HumanReviewer,
}

impl DecisionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Denylist => "denylist",
            Self::Allowlist => "allowlist",
            Self::PolicyCache => "policy_cache",
            Self::Scorer => "scorer",
            Self::AgentReviewer => "agent_reviewer",
            Self::HumanReviewer => "human_reviewer",
        }
    }
}

/// The permit0 permission engine.
///
/// Owns the normalizer registry, risk rules, scoring config, and store.
/// Immutable after construction via `EngineBuilder`.
pub struct Engine {
    registry: NormalizerRegistry,
    risk_rules: HashMap<String, RiskRuleDef>,
    config: ScoringConfig,
    store: Arc<dyn Store>,
    reviewer: Option<AgentReviewer>,
    // Audit subsystem (optional)
    audit_sink: Option<Arc<dyn AuditSink>>,
    audit_signer: Option<Arc<dyn AuditSigner>>,
    audit_redactor: Option<Arc<dyn Redactor>>,
    audit_policy: AuditPolicy,
    audit_sequence: std::sync::atomic::AtomicU64,
    audit_prev_hash: std::sync::Mutex<String>,
}

impl Engine {
    /// Evaluate a raw tool call and return a permission decision.
    ///
    /// Implements the §10 decision pipeline:
    /// 1. Normalize via registry
    /// 2. Denylist check
    /// 3. Allowlist check
    /// 4. Policy cache check
    /// 5. Unknown action type check
    /// 6. Risk scoring
    /// 7. Score → permission routing
    pub fn get_permission(
        &self,
        tool_call: &RawToolCall,
        ctx: &PermissionCtx,
    ) -> Result<PermissionResult, EngineError> {
        // Step 1: Normalize
        let norm = self.registry.normalize(tool_call, &ctx.normalize_ctx)?;
        self.run_pipeline(norm, tool_call, ctx)
    }

    /// Check a pre-built `NormAction` directly, skipping the normalizer step.
    ///
    /// Used by clients (e.g. language SDKs) that produce norm actions inline
    /// rather than going through a YAML normalizer. A synthetic raw tool call
    /// is constructed from the norm action's entities for risk-rule evaluation
    /// and audit logging.
    pub fn check_norm_action(
        &self,
        norm: NormAction,
        ctx: &PermissionCtx,
    ) -> Result<PermissionResult, EngineError> {
        // Synthesize a raw tool call from the entities so the post-normalize
        // pipeline (which expects raw_params for risk rules and tool_call for
        // audit) has something to work with.
        let synthetic = RawToolCall {
            tool_name: format!("__action:{}", norm.action_type.as_action_str()),
            parameters: serde_json::Value::Object(norm.entities.clone()),
            metadata: Default::default(),
        };
        self.run_pipeline(norm, &synthetic, ctx)
    }

    /// Steps 2–7 of the decision pipeline, shared between `get_permission`
    /// (which normalizes first) and `check_norm_action` (which doesn't).
    fn run_pipeline(
        &self,
        norm: NormAction,
        tool_call: &RawToolCall,
        ctx: &PermissionCtx,
    ) -> Result<PermissionResult, EngineError> {
        let norm_hash = norm.norm_hash();

        // Step 2: Denylist
        if self.store.denylist_check(&norm_hash)?.is_some() {
            let result = PermissionResult {
                permission: Permission::Deny,
                norm_action: norm,
                risk_score: None,
                source: DecisionSource::Denylist,
            };
            self.log_decision(&result, tool_call, ctx)?;
            return Ok(result);
        }

        // Step 3: Allowlist
        if self.store.allowlist_check(&norm_hash)? {
            let result = PermissionResult {
                permission: Permission::Allow,
                norm_action: norm,
                risk_score: None,
                source: DecisionSource::Allowlist,
            };
            self.log_decision(&result, tool_call, ctx)?;
            return Ok(result);
        }

        // Step 4: Policy cache
        if let Some(cached) = self.store.policy_cache_get(&norm_hash)? {
            let result = PermissionResult {
                permission: cached,
                norm_action: norm,
                risk_score: None,
                source: DecisionSource::PolicyCache,
            };
            self.log_decision(&result, tool_call, ctx)?;
            return Ok(result);
        }

        // Step 5: Unknown action type → deny with explanation
        let action_key = norm.action_type.as_action_str();
        if !self.risk_rules.contains_key(&action_key) {
            // No risk rule for this action type → Human-in-the-loop (conservative default)
            let permission = Permission::HumanInTheLoop;
            self.store.policy_cache_set(norm_hash, permission)?;
            let result = PermissionResult {
                permission,
                norm_action: norm,
                risk_score: None,
                source: DecisionSource::Scorer,
            };
            self.log_decision(&result, tool_call, ctx)?;
            return Ok(result);
        }

        // Step 6: Risk scoring (with session amplifier + block rules)
        let risk_score = self.assess(&tool_call.parameters, &norm, ctx.session.as_ref())?;

        // Step 7: Score → permission routing
        let base_permission = score_to_permission(risk_score.tier, risk_score.blocked);

        // Step 7b: Agent reviewer for MEDIUM tier
        let (permission, source) = if base_permission == Permission::HumanInTheLoop {
            if let Some(ref reviewer) = self.reviewer {
                let review_input = ReviewInput {
                    norm_action: norm.clone(),
                    risk_score: risk_score.clone(),
                    raw_tool_call: tool_call.clone(),
                    task_goal: ctx.task_goal.clone(),
                    session_summary: None,
                    org_policy: None,
                };
                let review = reviewer.handle_medium(&review_input, ctx.session.as_ref());
                let perm = match review.verdict {
                    ReviewVerdict::HumanInTheLoop => Permission::HumanInTheLoop,
                    ReviewVerdict::Deny => Permission::Deny,
                };
                (perm, DecisionSource::AgentReviewer)
            } else {
                (base_permission, DecisionSource::Scorer)
            }
        } else {
            (base_permission, DecisionSource::Scorer)
        };

        // Cache the result
        self.store.policy_cache_set(norm_hash, permission)?;

        let result = PermissionResult {
            permission,
            norm_action: norm,
            risk_score: Some(risk_score),
            source,
        };
        self.log_decision(&result, tool_call, ctx)?;
        Ok(result)
    }

    /// Perform risk assessment: apply risk rules to build template, then score.
    ///
    /// When a `SessionContext` is present:
    /// 1. Derive the `session` amplifier dimension automatically.
    /// 2. Evaluate YAML `session_rules` from the risk rule.
    /// 3. Evaluate built-in session block rules (privilege_escalation_then_exec, etc.).
    fn assess(
        &self,
        raw_params: &serde_json::Value,
        norm: &NormAction,
        session: Option<&SessionContext>,
    ) -> Result<RiskScore, EngineError> {
        let action_key = norm.action_type.as_action_str();
        let rule_def = self
            .risk_rules
            .get(&action_key)
            .ok_or_else(|| EngineError::NoRiskRule(action_key.clone()))?;

        // Rules evaluate against the raw parameters + a sibling `entity` object
        // containing normalized entities (host, is_private, amount_cents, etc.).
        // Rules written before entity exposure (and the vast majority of existing
        // rules) keep working because raw params are preserved at the top level;
        // newer rules can reference `entity.host: { in_set: ... }` etc.
        let merged_data = merge_raw_with_entities(raw_params, &norm.entities);

        // Execute per-call risk rules
        let mut template = execute_risk_rules_with_sets(
            rule_def,
            &merged_data,
            None,
            Some(&self.config.named_sets),
        );

        // Session-aware scoring
        if let Some(session_ctx) = session {
            // 1. Derive session amplifier
            let session_amp = session_amplifier_score(session_ctx);
            template.amplifiers.insert("session".into(), session_amp);

            // 2. Evaluate YAML session_rules (DSL-based)
            // Convert session to JSON for DSL evaluation
            let session_json = session_to_json(session_ctx);
            execute_session_rules_with_sets(
                rule_def,
                &mut template,
                &session_json,
                Some(&self.config.named_sets),
            );

            // 3. Evaluate built-in session block rules
            let block_result =
                evaluate_session_block_rules(session_ctx, &action_key, &norm.entities);
            if block_result.blocked {
                template.gate(
                    block_result
                        .reason
                        .as_deref()
                        .unwrap_or("session block rule"),
                );
            }
        }

        // Compute hybrid score
        let score = compute_hybrid(&template, &self.config, Some(&norm.action_type));
        Ok(score)
    }

    /// Access the underlying store (for list management).
    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    /// Build and persist a decision audit record.
    fn log_decision(
        &self,
        result: &PermissionResult,
        tool_call: &RawToolCall,
        ctx: &PermissionCtx,
    ) -> Result<(), EngineError> {
        // Caller (e.g. calibration daemon) intends to write a richer
        // composite record itself; don't double-log.
        if ctx.skip_audit {
            return Ok(());
        }
        let now = chrono::Utc::now().to_rfc3339();
        let entry_id = ulid::Ulid::new().to_string();

        // Always write the simple DecisionRecord to the Store
        let record = DecisionRecord {
            id: entry_id.clone(),
            norm_hash: result.norm_action.norm_hash(),
            action_type: result.norm_action.action_type.as_action_str(),
            channel: result.norm_action.channel.clone(),
            permission: result.permission,
            source: result.source.as_str().into(),
            tier: result.risk_score.as_ref().map(|s| s.tier),
            risk_raw: result.risk_score.as_ref().map(|s| s.raw),
            blocked: result.risk_score.as_ref().is_some_and(|s| s.blocked),
            flags: result
                .risk_score
                .as_ref()
                .map(|s| s.flags.clone())
                .unwrap_or_default(),
            timestamp: now.clone(),
            surface_tool: result.norm_action.execution.surface_tool.clone(),
            surface_command: result.norm_action.execution.surface_command.clone(),
            engine_permission: None,
            reviewer: None,
            reason: None,
        };
        if let Err(e) = self.store.save_decision(record) {
            tracing::warn!("failed to persist decision record: {e}");
        }

        // Write full AuditEntry if sink is configured
        if let (Some(sink), Some(signer)) = (&self.audit_sink, &self.audit_signer) {
            let raw_tool_call = if let Some(ref redactor) = self.audit_redactor {
                redactor.redact(&serde_json::to_value(tool_call).unwrap_or_default())
            } else {
                serde_json::to_value(tool_call).unwrap_or_default()
            };

            let sequence = self
                .audit_sequence
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            let prev_hash = {
                let guard = self.audit_prev_hash.lock().unwrap();
                guard.clone()
            };

            let mut entry = AuditEntry {
                entry_id,
                timestamp: now,
                sequence,
                decision: result.permission,
                decision_source: result.source.as_str().into(),
                norm_action: result.norm_action.clone(),
                norm_hash: result.norm_action.norm_hash(),
                raw_tool_call,
                risk_score: result.risk_score.clone(),
                scoring_detail: None,
                agent_id: String::new(),
                session_id: ctx.session.as_ref().map(|s| s.session_id.clone()),
                task_goal: ctx.task_goal.clone(),
                org_id: ctx.normalize_ctx.org_domain.clone().unwrap_or_default(),
                environment: String::new(),
                engine_version: env!("CARGO_PKG_VERSION").into(),
                pack_id: String::new(),
                pack_version: String::new(),
                dsl_version: "1.0".into(),
                human_review: None,
                engine_decision: None,
                token_id: None,
                prev_hash,
                entry_hash: String::new(),
                signature: String::new(),
                correction_of: None,
                failed_open_context: None,
                retroactive_decision: None,
            };

            entry.entry_hash = compute_entry_hash(&entry);
            entry.signature = signer.sign(&entry.entry_hash);

            // Update prev_hash for next entry
            {
                let mut guard = self.audit_prev_hash.lock().unwrap();
                *guard = entry.entry_hash.clone();
            }

            match sink.append(&entry) {
                Ok(()) => {}
                Err(e) => match self.audit_policy {
                    AuditPolicy::Strict => {
                        return Err(EngineError::AuditFailure(format!(
                            "audit sink failed (strict policy): {e}"
                        )));
                    }
                    AuditPolicy::BestEffort => {
                        tracing::warn!("audit sink failed (best_effort): {e}");
                    }
                },
            }
        }

        Ok(())
    }

    /// Append a calibrated audit entry to the audit chain.
    ///
    /// Used by the calibration daemon after a human submits a decision via
    /// the dashboard. The normal `log_decision` path is suppressed during
    /// calibration via `ctx.skip_audit` (so the chain never sees the
    /// engine's pre-calibration recommendation); this writes the composite
    /// record with the human's verdict in `human_review`, `decision` set
    /// to the post-calibration permission, and `engine_decision` set to
    /// what the engine would have decided (for override visibility in the
    /// dashboard).
    ///
    /// No-op if no audit sink is configured.
    pub fn log_calibrated_audit(
        &self,
        result: &PermissionResult,
        tool_call: &RawToolCall,
        ctx: &PermissionCtx,
        engine_permission: Permission,
        reviewer: String,
        reason: String,
    ) -> Result<(), EngineError> {
        let (sink, signer) = match (&self.audit_sink, &self.audit_signer) {
            (Some(sink), Some(signer)) => (sink, signer),
            _ => return Ok(()),
        };

        let now = chrono::Utc::now().to_rfc3339();
        let entry_id = ulid::Ulid::new().to_string();

        let raw_tool_call = if let Some(ref redactor) = self.audit_redactor {
            redactor.redact(&serde_json::to_value(tool_call).unwrap_or_default())
        } else {
            serde_json::to_value(tool_call).unwrap_or_default()
        };

        let sequence = self
            .audit_sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let prev_hash = {
            let guard = self.audit_prev_hash.lock().unwrap();
            guard.clone()
        };

        let mut entry = AuditEntry {
            entry_id,
            timestamp: now.clone(),
            sequence,
            decision: result.permission,
            decision_source: result.source.as_str().into(),
            norm_action: result.norm_action.clone(),
            norm_hash: result.norm_action.norm_hash(),
            raw_tool_call,
            risk_score: result.risk_score.clone(),
            scoring_detail: None,
            agent_id: String::new(),
            session_id: ctx.session.as_ref().map(|s| s.session_id.clone()),
            task_goal: ctx.task_goal.clone(),
            org_id: ctx.normalize_ctx.org_domain.clone().unwrap_or_default(),
            environment: String::new(),
            engine_version: env!("CARGO_PKG_VERSION").into(),
            pack_id: String::new(),
            pack_version: String::new(),
            dsl_version: "1.0".into(),
            human_review: Some(HumanReview {
                reviewer,
                decision: result.permission,
                reason,
                reviewed_at: now,
            }),
            engine_decision: Some(engine_permission),
            token_id: None,
            prev_hash,
            entry_hash: String::new(),
            signature: String::new(),
            correction_of: None,
            failed_open_context: None,
            retroactive_decision: None,
        };

        entry.entry_hash = compute_entry_hash(&entry);
        entry.signature = signer.sign(&entry.entry_hash);

        {
            let mut guard = self.audit_prev_hash.lock().unwrap();
            *guard = entry.entry_hash.clone();
        }

        match sink.append(&entry) {
            Ok(()) => Ok(()),
            Err(e) => match self.audit_policy {
                AuditPolicy::Strict => Err(EngineError::AuditFailure(format!(
                    "audit sink failed (strict policy): {e}"
                ))),
                AuditPolicy::BestEffort => {
                    tracing::warn!("audit sink failed (best_effort): {e}");
                    Ok(())
                }
            },
        }
    }

    /// Reconstruct an audit entry from a client-side `FailOpenBuffer` event.
    ///
    /// Two facts are recorded:
    ///   - `decision: Allow` — the action ran on the client because policy
    ///     review was unreachable. We record what actually happened.
    ///   - `retroactive_decision: <whatever current pack says>` — what the
    ///     pack would say *now*. Auditors compare the two to find calls
    ///     that should not have run.
    ///
    /// `decision_source` is `"failed_open"`. The chain hash includes both
    /// the failed-open context and the retroactive decision, so tampering
    /// with either is detectable. Returns the entry_id used (a fresh ULID
    /// independent of the client's event_id, which is captured separately
    /// inside `failed_open_context` for forensic linkage).
    pub fn log_failed_open_replay(
        &self,
        tool_call: &RawToolCall,
        ctx: &PermissionCtx,
        retroactive_result: &PermissionResult,
        failed_open_context: FailedOpenContext,
    ) -> Result<String, EngineError> {
        let now = chrono::Utc::now().to_rfc3339();
        let entry_id = ulid::Ulid::new().to_string();

        // Failed-open replay does not write a DecisionRecord — the action
        // already ran on the client; this entry is purely for the audit
        // chain. The dashboard's audit-log query reads from the AuditSink,
        // so the failed-open window surfaces there.

        if let (Some(sink), Some(signer)) = (&self.audit_sink, &self.audit_signer) {
            let raw_tool_call = if let Some(ref redactor) = self.audit_redactor {
                redactor.redact(&serde_json::to_value(tool_call).unwrap_or_default())
            } else {
                serde_json::to_value(tool_call).unwrap_or_default()
            };

            let sequence = self
                .audit_sequence
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            let prev_hash = {
                let guard = self.audit_prev_hash.lock().unwrap();
                guard.clone()
            };

            let mut entry = AuditEntry {
                entry_id: entry_id.clone(),
                timestamp: now,
                sequence,
                decision: Permission::Allow,
                decision_source: "failed_open".into(),
                norm_action: retroactive_result.norm_action.clone(),
                norm_hash: retroactive_result.norm_action.norm_hash(),
                raw_tool_call,
                risk_score: retroactive_result.risk_score.clone(),
                scoring_detail: None,
                agent_id: String::new(),
                session_id: ctx.session.as_ref().map(|s| s.session_id.clone()),
                task_goal: ctx.task_goal.clone(),
                org_id: ctx.normalize_ctx.org_domain.clone().unwrap_or_default(),
                environment: String::new(),
                engine_version: env!("CARGO_PKG_VERSION").into(),
                pack_id: String::new(),
                pack_version: String::new(),
                dsl_version: "1.0".into(),
                human_review: None,
                engine_decision: None,
                token_id: None,
                prev_hash,
                entry_hash: String::new(),
                signature: String::new(),
                correction_of: None,
                failed_open_context: Some(failed_open_context),
                retroactive_decision: Some(retroactive_result.permission),
            };

            entry.entry_hash = compute_entry_hash(&entry);
            entry.signature = signer.sign(&entry.entry_hash);

            {
                let mut guard = self.audit_prev_hash.lock().unwrap();
                *guard = entry.entry_hash.clone();
            }

            match sink.append(&entry) {
                Ok(()) => {}
                Err(e) => match self.audit_policy {
                    AuditPolicy::Strict => {
                        return Err(EngineError::AuditFailure(format!(
                            "audit sink failed (strict policy): {e}"
                        )));
                    }
                    AuditPolicy::BestEffort => {
                        tracing::warn!("audit sink failed (best_effort): {e}");
                    }
                },
            }
        }

        Ok(entry_id)
    }
}

/// Map risk tier + blocked status to permission decision.
///
/// | Tier | Blocked | Permission |
/// |------|---------|------------|
/// | any | true | Deny |
/// | Minimal | false | Allow |
/// | Low | false | Allow |
/// | Medium | false | HumanInTheLoop |
/// | High | false | HumanInTheLoop |
/// | Critical | false | Deny |
fn score_to_permission(tier: Tier, blocked: bool) -> Permission {
    if blocked {
        return Permission::Deny;
    }
    match tier {
        Tier::Minimal | Tier::Low => Permission::Allow,
        Tier::Medium | Tier::High => Permission::HumanInTheLoop,
        Tier::Critical => Permission::Deny,
    }
}

/// Build the JSON value passed to risk-rule evaluation: raw tool params at the
/// top level plus an `entity` sub-object containing the normalizer-computed
/// entities. Rules can now use either path:
///
/// - legacy: `when: url: { contains: "localhost" }` — matches raw param
/// - new:    `when: entity.host: { in_set: "org.trusted_domains" }` — matches entity
///
/// If the raw params already have an `entity` key at the top level (vanishingly
/// rare, and semantically weird) we preserve it untouched and skip the injection
/// to avoid silent shadowing.
fn merge_raw_with_entities(
    raw_params: &serde_json::Value,
    entities: &permit0_types::Entities,
) -> serde_json::Value {
    let mut out = match raw_params {
        serde_json::Value::Object(m) => m.clone(),
        _ => {
            let mut m = serde_json::Map::new();
            m.insert("_raw".into(), raw_params.clone());
            m
        }
    };

    if !out.contains_key("entity") {
        let entity_obj: serde_json::Map<String, serde_json::Value> = entities
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        out.insert("entity".into(), serde_json::Value::Object(entity_obj));
    }

    serde_json::Value::Object(out)
}

/// Convert a SessionContext to a JSON value for DSL session rule evaluation.
///
/// The resulting JSON has fields like `daily_total`, `rate_per_minute`, etc.
/// that session rules in YAML can match against.
fn session_to_json(session: &SessionContext) -> serde_json::Value {
    use permit0_session::SessionFilter;
    let filter_all = SessionFilter::new();

    let mut map = serde_json::Map::new();
    map.insert(
        "session_id".into(),
        serde_json::Value::String(session.session_id.clone()),
    );
    map.insert(
        "record_count".into(),
        serde_json::json!(session.records.len()),
    );
    map.insert(
        "max_tier".into(),
        serde_json::Value::String(session.max_tier().to_string()),
    );
    map.insert(
        "duration_minutes".into(),
        serde_json::json!(session.duration_minutes()),
    );
    map.insert(
        "distinct_flags".into(),
        serde_json::json!(session.distinct_flags(None)),
    );

    // Aggregate common fields for convenience
    // Sum of "amount" across all records (commonly used)
    let total_amount = session.sum("amount", &filter_all);
    map.insert("total_amount".into(), serde_json::json!(total_amount));

    // Legacy compatibility: daily_total alias
    map.insert("daily_total".into(), serde_json::json!(total_amount));

    serde_json::Value::Object(map)
}

// ── EngineBuilder ──

/// Builder for constructing a configured `Engine`.
pub struct EngineBuilder {
    registry: NormalizerRegistry,
    risk_rules: HashMap<String, RiskRuleDef>,
    config: ScoringConfig,
    store: Option<Arc<dyn Store>>,
    reviewer: Option<AgentReviewer>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    audit_signer: Option<Arc<dyn AuditSigner>>,
    audit_redactor: Option<Arc<dyn Redactor>>,
    audit_policy: AuditPolicy,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self {
            registry: NormalizerRegistry::new(),
            risk_rules: HashMap::new(),
            config: ScoringConfig::default(),
            store: None,
            reviewer: None,
            audit_sink: None,
            audit_signer: None,
            audit_redactor: None,
            audit_policy: AuditPolicy::default(),
        }
    }

    /// Set a custom scoring config.
    pub fn with_config(mut self, config: ScoringConfig) -> Self {
        self.config = config;
        self
    }

    /// Set a custom store implementation.
    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Use a SQLite store at the given path.
    pub fn with_sqlite(self, path: impl AsRef<std::path::Path>) -> Result<Self, EngineError> {
        let store = permit0_store::SqliteStore::open(path)
            .map_err(|e| EngineError::Build(e.to_string()))?;
        Ok(self.with_store(Arc::new(store)))
    }

    /// Set an agent reviewer for MEDIUM-tier calls.
    pub fn with_reviewer(mut self, reviewer: AgentReviewer) -> Self {
        self.reviewer = Some(reviewer);
        self
    }

    /// Configure the audit subsystem.
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>, signer: Arc<dyn AuditSigner>) -> Self {
        self.audit_sink = Some(sink);
        self.audit_signer = Some(signer);
        self
    }

    /// Set the audit policy (strict or best_effort).
    pub fn with_audit_policy(mut self, policy: AuditPolicy) -> Self {
        self.audit_policy = policy;
        self
    }

    /// Set the audit redactor.
    pub fn with_audit_redactor(mut self, redactor: Arc<dyn Redactor>) -> Self {
        self.audit_redactor = Some(redactor);
        self
    }

    /// Install a YAML normalizer from a parsed definition.
    pub fn install_normalizer(mut self, normalizer: DslNormalizer) -> Result<Self, EngineError> {
        self.registry
            .register(Arc::new(normalizer))
            .map_err(|e| EngineError::Build(e.to_string()))?;
        Ok(self)
    }

    /// Install a YAML normalizer from a YAML string.
    pub fn install_normalizer_yaml(self, yaml: &str) -> Result<Self, EngineError> {
        let normalizer =
            DslNormalizer::from_yaml(yaml).map_err(|e| EngineError::Build(e.to_string()))?;
        self.install_normalizer(normalizer)
    }

    /// Install a native (Rust-coded) normalizer.
    pub fn install_native(mut self, normalizer: Arc<dyn Normalizer>) -> Result<Self, EngineError> {
        self.registry
            .register(normalizer)
            .map_err(|e| EngineError::Build(e.to_string()))?;
        Ok(self)
    }

    /// Install a risk rule definition.
    pub fn install_risk_rule(mut self, rule_def: RiskRuleDef) -> Result<Self, EngineError> {
        let validation_errors = validate::validate_risk_rule(&rule_def);
        if !validation_errors.is_empty() {
            let msgs: Vec<String> = validation_errors.iter().map(|e| e.to_string()).collect();
            return Err(EngineError::Build(format!(
                "risk rule validation failed: {}",
                msgs.join("; ")
            )));
        }
        self.risk_rules
            .insert(rule_def.action_type.clone(), rule_def);
        Ok(self)
    }

    /// Install a risk rule from a YAML string.
    pub fn install_risk_rule_yaml(self, yaml: &str) -> Result<Self, EngineError> {
        let rule_def: RiskRuleDef =
            serde_yaml::from_str(yaml).map_err(|e| EngineError::Build(e.to_string()))?;
        self.install_risk_rule(rule_def)
    }

    /// Install a tool-name alias YAML document. Aliases let foreign tool
    /// names (e.g. Google's official Gmail MCP `create_label`) be
    /// rewritten to the canonical names normalizers match
    /// (`gmail_create_mailbox`). See [`permit0_normalize::AliasResolver`]
    /// for the YAML schema.
    pub fn install_aliases_yaml(mut self, yaml: &str) -> Result<Self, EngineError> {
        self.registry
            .install_aliases_yaml(yaml)
            .map_err(|e| EngineError::Build(e.to_string()))?;
        Ok(self)
    }

    /// Build the engine. Uses `InMemoryStore` if no store was provided.
    pub fn build(self) -> Result<Engine, EngineError> {
        let store = self.store.unwrap_or_else(|| Arc::new(InMemoryStore::new()));

        Ok(Engine {
            registry: self.registry,
            risk_rules: self.risk_rules,
            config: self.config,
            store,
            reviewer: self.reviewer,
            audit_sink: self.audit_sink,
            audit_signer: self.audit_signer,
            audit_redactor: self.audit_redactor,
            audit_policy: self.audit_policy,
            audit_sequence: std::sync::atomic::AtomicU64::new(0),
            audit_prev_hash: std::sync::Mutex::new(GENESIS_HASH.into()),
        })
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_normalize::NormalizeCtx;
    use serde_json::json;

    const GMAIL_NORM_YAML: &str = include_str!("../../../packs/email/normalizers/gmail_send.yaml");
    const OUTLOOK_NORM_YAML: &str =
        include_str!("../../../packs/email/normalizers/outlook_send.yaml");
    const EMAIL_RISK_YAML: &str = include_str!("../../../packs/email/risk_rules/send.yaml");

    fn build_test_engine() -> Engine {
        EngineBuilder::new()
            .install_normalizer_yaml(GMAIL_NORM_YAML)
            .unwrap()
            .install_normalizer_yaml(OUTLOOK_NORM_YAML)
            .unwrap()
            .install_risk_rule_yaml(EMAIL_RISK_YAML)
            .unwrap()
            .build()
            .unwrap()
    }

    fn gmail_send(subject: &str, body: &str) -> RawToolCall {
        RawToolCall {
            tool_name: "gmail_send".into(),
            parameters: json!({
                "to": "bob@external.com",
                "subject": subject,
                "body": body,
            }),
            metadata: Default::default(),
        }
    }

    fn outlook_send(subject: &str, body: &str) -> RawToolCall {
        RawToolCall {
            tool_name: "outlook_send".into(),
            parameters: json!({
                "to": "alice@external.com",
                "subject": subject,
                "body": body,
            }),
            metadata: Default::default(),
        }
    }

    fn default_ctx() -> PermissionCtx {
        PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"))
    }

    #[test]
    fn score_to_permission_mapping() {
        assert_eq!(score_to_permission(Tier::Minimal, false), Permission::Allow);
        assert_eq!(score_to_permission(Tier::Low, false), Permission::Allow);
        assert_eq!(
            score_to_permission(Tier::Medium, false),
            Permission::HumanInTheLoop
        );
        assert_eq!(
            score_to_permission(Tier::High, false),
            Permission::HumanInTheLoop
        );
        assert_eq!(score_to_permission(Tier::Critical, false), Permission::Deny);
        // Blocked always deny
        assert_eq!(score_to_permission(Tier::Minimal, true), Permission::Deny);
    }

    #[test]
    fn engine_build_and_score() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        // Plain email → should score, allow
        let result = engine
            .get_permission(&gmail_send("Hello", "ok"), &ctx)
            .unwrap();
        assert_eq!(result.source, DecisionSource::Scorer);
        assert!(result.risk_score.is_some());
    }

    #[test]
    fn outlook_normalizer_works() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        let result = engine
            .get_permission(&outlook_send("Hi", "body"), &ctx)
            .unwrap();
        assert_eq!(result.norm_action.action_type.as_action_str(), "email.send");
        assert_eq!(result.norm_action.channel, "outlook");
    }

    #[test]
    fn denylist_blocks() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        // First, get the norm_hash
        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        let hash = result.norm_action.norm_hash();

        // Clear cache, add to denylist
        engine.store().policy_cache_invalidate(&hash).unwrap();
        engine.store().denylist_add(hash, "blocked".into()).unwrap();

        // Now should deny
        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert_eq!(result.permission, Permission::Deny);
        assert_eq!(result.source, DecisionSource::Denylist);
    }

    #[test]
    fn allowlist_allows() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        let hash = result.norm_action.norm_hash();

        engine.store().policy_cache_invalidate(&hash).unwrap();
        engine
            .store()
            .allowlist_add(hash, "approved".into())
            .unwrap();

        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert_eq!(result.permission, Permission::Allow);
        assert_eq!(result.source, DecisionSource::Allowlist);
    }

    #[test]
    fn denylist_wins_over_allowlist() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        let hash = result.norm_action.norm_hash();

        engine.store().policy_cache_invalidate(&hash).unwrap();
        engine
            .store()
            .allowlist_add(hash, "approved".into())
            .unwrap();
        engine.store().denylist_add(hash, "blocked".into()).unwrap();

        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert_eq!(result.permission, Permission::Deny);
        assert_eq!(result.source, DecisionSource::Denylist);
    }

    #[test]
    fn policy_cache_hit() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        // First call → scorer
        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert_eq!(result.source, DecisionSource::Scorer);
        let first_permission = result.permission;

        // Second call → cache
        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert_eq!(result.source, DecisionSource::PolicyCache);
        assert_eq!(result.permission, first_permission);
    }

    #[test]
    fn unknown_action_type_returns_human() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        // A tool that normalizes but has no risk rule
        let raw = RawToolCall {
            tool_name: "unknown_tool".into(),
            parameters: json!({"some": "data"}),
            metadata: Default::default(),
        };
        let result = engine.get_permission(&raw, &ctx).unwrap();
        // Falls through to fallback normalizer → unknown.unclassified → no risk rule → HITL
        assert_eq!(result.permission, Permission::HumanInTheLoop);
    }

    // ── Session-aware scoring tests ─────────────────────────────

    #[test]
    fn session_amplifier_wired_into_scoring() {
        let engine = build_test_engine();
        let mut session = SessionContext::new("test-session");

        // Add some high-tier records to elevate session amplifier
        for i in 0..3 {
            session.push(permit0_session::ActionRecord {
                action_type: "email.send".into(),
                tier: Tier::High,
                flags: vec!["OUTBOUND".into()],
                timestamp: 1_700_000_000.0 + i as f64,
                entities: serde_json::Map::new(),
            });
        }

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"))
            .with_session(session);

        // Score with session context — session amplifier should be injected
        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert!(result.risk_score.is_some());
    }

    #[test]
    fn no_session_still_works() {
        // Verify that passing no session context doesn't break anything
        let engine = build_test_engine();
        let ctx = default_ctx();
        let result = engine
            .get_permission(&gmail_send("Hello", "body"), &ctx)
            .unwrap();
        assert_eq!(result.source, DecisionSource::Scorer);
        assert!(result.risk_score.is_some());
    }

    // ── Failed-open replay (Lane A step 1b) ──────────────────────────

    fn build_test_engine_with_audit() -> (Engine, Arc<permit0_store::audit::InMemoryAuditSink>) {
        let signer = Arc::new(permit0_store::audit::Ed25519Signer::generate());
        let sink = Arc::new(permit0_store::audit::InMemoryAuditSink::new());
        let engine = EngineBuilder::new()
            .install_normalizer_yaml(GMAIL_NORM_YAML)
            .unwrap()
            .install_normalizer_yaml(OUTLOOK_NORM_YAML)
            .unwrap()
            .install_risk_rule_yaml(EMAIL_RISK_YAML)
            .unwrap()
            .with_audit(sink.clone() as Arc<dyn AuditSink>, signer)
            .build()
            .unwrap();
        (engine, sink)
    }

    fn sample_failed_open_context() -> FailedOpenContext {
        FailedOpenContext {
            fail_reason_code: "refused".into(),
            fail_reason: "ECONNREFUSED".into(),
            client_window_start: "2026-04-30T10:00:00Z".into(),
            client_window_end: "2026-04-30T10:05:00Z".into(),
            client_version: "0.1.0".into(),
            fail_open_source: "env_var".into(),
        }
    }

    #[test]
    fn failed_open_replay_writes_audit_entry() {
        let (engine, sink) = build_test_engine_with_audit();
        let ctx = default_ctx();

        // Pretend the original tool call ran during a daemon outage.
        let tool_call = gmail_send("Hello", "body");

        // Retro-score the same call against the current pack.
        let mut retro_ctx = default_ctx();
        retro_ctx = retro_ctx.with_skip_audit(true);
        let retro = engine.get_permission(&tool_call, &retro_ctx).unwrap();

        let entry_id = engine
            .log_failed_open_replay(&tool_call, &ctx, &retro, sample_failed_open_context())
            .unwrap();

        // The sink received exactly one entry, with the right flavor.
        let entries = sink.all_entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.entry_id, entry_id);
        assert_eq!(e.decision_source, "failed_open");
        assert_eq!(e.decision, Permission::Allow); // it ran
        assert!(e.failed_open_context.is_some());
        assert_eq!(e.retroactive_decision, Some(retro.permission));
    }

    #[test]
    fn failed_open_replay_chain_is_continuous() {
        let (engine, sink) = build_test_engine_with_audit();
        let ctx = default_ctx();

        // Mix one normal entry, one replay, one normal — ensure the chain
        // sequence numbers are monotonic and prev_hash links are intact.
        let tc1 = gmail_send("first", "body");
        engine.get_permission(&tc1, &ctx).unwrap();

        let tc2 = gmail_send("replayed", "body");
        let mut retro_ctx = default_ctx();
        retro_ctx = retro_ctx.with_skip_audit(true);
        let retro = engine.get_permission(&tc2, &retro_ctx).unwrap();
        engine
            .log_failed_open_replay(&tc2, &ctx, &retro, sample_failed_open_context())
            .unwrap();

        let tc3 = gmail_send("third", "body");
        engine.get_permission(&tc3, &ctx).unwrap();

        let entries = sink.all_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[2].sequence, 3);

        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
        assert_eq!(entries[2].prev_hash, entries[1].entry_hash);

        // The replay entry is distinguishable by decision_source.
        assert_eq!(entries[1].decision_source, "failed_open");
        assert_ne!(entries[0].decision_source, "failed_open");
        assert_ne!(entries[2].decision_source, "failed_open");
    }

    #[test]
    fn failed_open_replay_threads_session_and_task_goal() {
        let (engine, sink) = build_test_engine_with_audit();
        let ctx = default_ctx()
            .with_session(SessionContext::new("conv-99"))
            .with_task_goal("send the report");

        let tool_call = gmail_send("report", "body");
        let retro = engine
            .get_permission(&tool_call, &default_ctx().with_skip_audit(true))
            .unwrap();
        engine
            .log_failed_open_replay(&tool_call, &ctx, &retro, sample_failed_open_context())
            .unwrap();

        let entries = sink.all_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id.as_deref(), Some("conv-99"));
        assert_eq!(entries[0].task_goal.as_deref(), Some("send the report"));
    }

    #[test]
    fn failed_open_replay_no_op_without_audit_sink() {
        // No sink configured → method still succeeds and returns an
        // entry_id, but writes nothing. Mirrors log_decision behavior so
        // callers don't have to know whether audit is wired up.
        let engine = build_test_engine();
        let ctx = default_ctx();
        let tool_call = gmail_send("Hello", "body");
        let retro = engine
            .get_permission(&tool_call, &default_ctx().with_skip_audit(true))
            .unwrap();
        let entry_id = engine
            .log_failed_open_replay(&tool_call, &ctx, &retro, sample_failed_open_context())
            .unwrap();
        assert!(!entry_id.is_empty()); // ULID returned even without sink
    }

    // ── Calibration audit path ────────────────────────────────────────

    #[test]
    fn calibrated_audit_writes_entry_with_human_review() {
        // Mirrors the daemon's calibration flow: get_permission with
        // skip_audit=true (suppressed engine write) → human approves →
        // log_calibrated_audit(...) appends the composite entry. The
        // dashboard's audit log reads from this sink, so without the
        // composite write nothing surfaces.
        let (engine, sink) = build_test_engine_with_audit();
        let ctx = default_ctx().with_skip_audit(true);
        let tool_call = gmail_send("Hello", "body");

        // Engine pass — its own log_decision early-returns due to
        // skip_audit, so the sink stays empty here.
        let result = engine.get_permission(&tool_call, &ctx).unwrap();
        assert!(sink.all_entries().is_empty());

        // Now the human's verdict comes back; record it. Pretend the
        // engine had said HumanInTheLoop and the human overrode to Allow
        // (the actual `result.permission` is what the engine returned,
        // since calibration daemon would mutate it post-hoc — for this
        // test we just thread distinct values through).
        engine
            .log_calibrated_audit(
                &result,
                &tool_call,
                &ctx,
                Permission::HumanInTheLoop,
                "su@example.com".into(),
                "looks fine".into(),
            )
            .unwrap();

        let entries = sink.all_entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.decision, result.permission);
        let hr = e.human_review.as_ref().expect("human_review populated");
        assert_eq!(hr.reviewer, "su@example.com");
        assert_eq!(hr.reason, "looks fine");
        assert_eq!(hr.decision, result.permission);
        assert!(!hr.reviewed_at.is_empty());
        assert_eq!(e.engine_decision, Some(Permission::HumanInTheLoop));
    }

    #[test]
    fn calibrated_audit_chain_links_with_normal_entries() {
        // A calibrated entry must thread through the chain like any other —
        // sequence monotonic, prev_hash linking back to the previous entry.
        let (engine, sink) = build_test_engine_with_audit();

        // One normal entry first.
        let tc1 = gmail_send("first", "body");
        engine.get_permission(&tc1, &default_ctx()).unwrap();

        // Then a calibrated one.
        let tc2 = gmail_send("second", "body");
        let cal_ctx = default_ctx().with_skip_audit(true);
        let result2 = engine.get_permission(&tc2, &cal_ctx).unwrap();
        engine
            .log_calibrated_audit(
                &result2,
                &tc2,
                &cal_ctx,
                Permission::HumanInTheLoop,
                "su".into(),
                "approve".into(),
            )
            .unwrap();

        // Then another normal one.
        let tc3 = gmail_send("third", "body");
        engine.get_permission(&tc3, &default_ctx()).unwrap();

        let entries = sink.all_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[2].sequence, 3);
        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
        assert_eq!(entries[2].prev_hash, entries[1].entry_hash);

        assert!(entries[0].human_review.is_none());
        assert!(entries[1].human_review.is_some());
        assert!(entries[2].human_review.is_none());
    }

    #[test]
    fn calibrated_audit_no_op_without_sink() {
        // If audit isn't wired up, the call is a no-op and returns Ok —
        // callers don't have to branch on sink presence.
        let engine = build_test_engine();
        let ctx = default_ctx().with_skip_audit(true);
        let tool_call = gmail_send("Hello", "body");
        let result = engine.get_permission(&tool_call, &ctx).unwrap();

        engine
            .log_calibrated_audit(
                &result,
                &tool_call,
                &ctx,
                Permission::HumanInTheLoop,
                "su".into(),
                "ok".into(),
            )
            .unwrap();
    }
}
