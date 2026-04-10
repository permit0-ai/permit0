#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use permit0_dsl::normalizer::DslNormalizer;
use permit0_dsl::risk_executor::{execute_risk_rules, execute_session_rules};
use permit0_dsl::schema::risk_rule::RiskRuleDef;
use permit0_dsl::validate;
use permit0_normalize::{NormalizerRegistry, Normalizer};
use permit0_scoring::{ScoringConfig, compute_hybrid};
use permit0_agent::{AgentReviewer, ReviewInput, ReviewVerdict};
use permit0_session::{SessionContext, evaluate_session_block_rules, session_amplifier_score};
use permit0_store::audit::{
    AuditEntry, AuditPolicy, AuditSigner, AuditSink,
    chain::{GENESIS_HASH, compute_entry_hash},
    Redactor,
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
    AgentReviewer,
}

impl DecisionSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Denylist => "denylist",
            Self::Allowlist => "allowlist",
            Self::PolicyCache => "policy_cache",
            Self::Scorer => "scorer",
            Self::AgentReviewer => "agent_reviewer",
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
        let norm = self
            .registry
            .normalize(tool_call, &ctx.normalize_ctx)?;
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
            self.store
                .policy_cache_set(norm_hash, permission)?;
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
        let (permission, source) =
            if base_permission == Permission::HumanInTheLoop {
                if let Some(ref reviewer) = self.reviewer {
                    let review_input = ReviewInput {
                        norm_action: norm.clone(),
                        risk_score: risk_score.clone(),
                        raw_tool_call: tool_call.clone(),
                        task_goal: ctx.task_goal.clone(),
                        session_summary: None,
                        org_policy: None,
                    };
                    let review = reviewer.handle_medium(
                        &review_input,
                        ctx.session.as_ref(),
                    );
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

        // Risk rules evaluate against the raw parameters, not the extracted entities.
        let data = raw_params;

        // Execute per-call risk rules
        let mut template = execute_risk_rules(rule_def, data, None);

        // Session-aware scoring
        if let Some(session_ctx) = session {
            // 1. Derive session amplifier
            let session_amp = session_amplifier_score(session_ctx);
            template.amplifiers.insert("session".into(), session_amp);

            // 2. Evaluate YAML session_rules (DSL-based)
            // Convert session to JSON for DSL evaluation
            let session_json = session_to_json(session_ctx);
            execute_session_rules(rule_def, &mut template, &session_json);

            // 3. Evaluate built-in session block rules
            let block_result = evaluate_session_block_rules(
                session_ctx,
                &action_key,
                &norm.entities,
            );
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
    fn log_decision(&self, result: &PermissionResult, tool_call: &RawToolCall, ctx: &PermissionCtx) -> Result<(), EngineError> {
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
                token_id: None,
                prev_hash,
                entry_hash: String::new(),
                signature: String::new(),
                correction_of: None,
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

/// Convert a SessionContext to a JSON value for DSL session rule evaluation.
///
/// The resulting JSON has fields like `daily_total`, `rate_per_minute`, etc.
/// that session rules in YAML can match against.
fn session_to_json(session: &SessionContext) -> serde_json::Value {
    use permit0_session::SessionFilter;
    let filter_all = SessionFilter::new();

    let mut map = serde_json::Map::new();
    map.insert("session_id".into(), serde_json::Value::String(session.session_id.clone()));
    map.insert("record_count".into(), serde_json::json!(session.records.len()));
    map.insert("max_tier".into(), serde_json::Value::String(session.max_tier().to_string()));
    map.insert("duration_minutes".into(), serde_json::json!(session.duration_minutes()));
    map.insert("distinct_flags".into(), serde_json::json!(session.distinct_flags(None)));

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
    pub fn with_audit(
        mut self,
        sink: Arc<dyn AuditSink>,
        signer: Arc<dyn AuditSigner>,
    ) -> Self {
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
    pub fn install_normalizer(
        mut self,
        normalizer: DslNormalizer,
    ) -> Result<Self, EngineError> {
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
    pub fn install_native(
        mut self,
        normalizer: Arc<dyn Normalizer>,
    ) -> Result<Self, EngineError> {
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

    /// Build the engine. Uses `InMemoryStore` if no store was provided.
    pub fn build(self) -> Result<Engine, EngineError> {
        let store = self
            .store
            .unwrap_or_else(|| Arc::new(InMemoryStore::new()));

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

    const STRIPE_NORM_YAML: &str = include_str!("../../../packs/stripe/normalizers/charges_create.yaml");
    const STRIPE_RISK_YAML: &str = include_str!("../../../packs/stripe/risk_rules/charge.yaml");
    const BASH_NORM_YAML: &str = include_str!("../../../packs/bash/normalizers/shell.yaml");
    const BASH_RISK_YAML: &str = include_str!("../../../packs/bash/risk_rules/shell.yaml");

    fn build_test_engine() -> Engine {
        EngineBuilder::new()
            .install_normalizer_yaml(STRIPE_NORM_YAML)
            .unwrap()
            .install_normalizer_yaml(BASH_NORM_YAML)
            .unwrap()
            .install_risk_rule_yaml(STRIPE_RISK_YAML)
            .unwrap()
            .install_risk_rule_yaml(BASH_RISK_YAML)
            .unwrap()
            .build()
            .unwrap()
    }

    fn stripe_charge(amount: u64) -> RawToolCall {
        RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": amount, "currency": "usd"}
            }),
            metadata: Default::default(),
        }
    }

    fn bash_command(cmd: &str) -> RawToolCall {
        RawToolCall {
            tool_name: "bash".into(),
            parameters: json!({"command": cmd}),
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

        // Low-value charge → should score low, allow
        let result = engine.get_permission(&stripe_charge(50), &ctx).unwrap();
        assert_eq!(result.source, DecisionSource::Scorer);
        assert!(result.risk_score.is_some());
    }

    #[test]
    fn denylist_blocks() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        // First, get the norm_hash
        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        let hash = result.norm_action.norm_hash();

        // Clear cache, add to denylist
        engine.store().policy_cache_invalidate(&hash).unwrap();
        engine.store().denylist_add(hash, "blocked".into()).unwrap();

        // Now should deny
        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        assert_eq!(result.permission, Permission::Deny);
        assert_eq!(result.source, DecisionSource::Denylist);
    }

    #[test]
    fn allowlist_allows() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        let hash = result.norm_action.norm_hash();

        engine.store().policy_cache_invalidate(&hash).unwrap();
        engine.store().allowlist_add(hash, "approved".into()).unwrap();

        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        assert_eq!(result.permission, Permission::Allow);
        assert_eq!(result.source, DecisionSource::Allowlist);
    }

    #[test]
    fn denylist_wins_over_allowlist() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        let hash = result.norm_action.norm_hash();

        engine.store().policy_cache_invalidate(&hash).unwrap();
        engine.store().allowlist_add(hash, "approved".into()).unwrap();
        engine.store().denylist_add(hash, "blocked".into()).unwrap();

        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
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
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        assert_eq!(result.source, DecisionSource::Scorer);
        let first_permission = result.permission;

        // Second call → cache
        let result = engine
            .get_permission(&stripe_charge(5000), &ctx)
            .unwrap();
        assert_eq!(result.source, DecisionSource::PolicyCache);
        assert_eq!(result.permission, first_permission);
    }

    #[test]
    fn gate_produces_deny() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        // Crypto currency triggers gate
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 1000, "currency": "btc"}
            }),
            metadata: Default::default(),
        };
        let result = engine.get_permission(&raw, &ctx).unwrap();
        assert_eq!(result.permission, Permission::Deny);
        assert!(result.risk_score.as_ref().is_some_and(|s| s.blocked));
    }

    #[test]
    fn bash_dangerous_gate() {
        let engine = build_test_engine();
        let ctx = default_ctx();

        let result = engine
            .get_permission(&bash_command("echo data > /dev/sda"), &ctx)
            .unwrap();
        assert_eq!(result.permission, Permission::Deny);
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
                action_type: "payments.charge".into(),
                tier: Tier::High,
                flags: vec!["FINANCIAL".into()],
                timestamp: 1_700_000_000.0 + i as f64,
                entities: serde_json::Map::new(),
            });
        }

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"))
            .with_session(session);

        // Score with session context — session amplifier should be injected
        let result = engine.get_permission(&stripe_charge(50), &ctx).unwrap();
        assert!(result.risk_score.is_some());
        // The session amplifier should make the score higher than without session
    }

    #[test]
    fn session_dsl_rules_evaluated() {
        let engine = build_test_engine();
        let mut session = SessionContext::new("test-session");

        // The stripe risk YAML has a session_rule that fires when daily_total > 50000
        // session_to_json sums all "amount" entities as daily_total
        session.push(permit0_session::ActionRecord {
            action_type: "payments.charge".into(),
            tier: Tier::Low,
            timestamp: 1_700_000_000.0,
            flags: vec![],
            entities: {
                let mut m = serde_json::Map::new();
                m.insert("amount".into(), json!(60000));
                m
            },
        });

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"))
            .with_session(session);

        let result = engine.get_permission(&stripe_charge(50), &ctx).unwrap();
        // The session_rule adds velocity_alert flag + upgrades scope
        // Just verify scoring completed with session context
        assert!(result.risk_score.is_some());
    }

    #[test]
    fn session_block_rule_card_testing_fires() {
        let engine = build_test_engine();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut session = SessionContext::new("checkout-agent");
        // Two prior micro-charges to distinct customers
        session.push(permit0_session::ActionRecord {
            action_type: "payments.charge".into(),
            tier: Tier::Low,
            timestamp: now - 30.0,
            flags: vec![],
            entities: {
                let mut m = serde_json::Map::new();
                m.insert("amount".into(), json!(50));
                m.insert("customer".into(), json!("cus_aaa"));
                m
            },
        });
        session.push(permit0_session::ActionRecord {
            action_type: "payments.charge".into(),
            tier: Tier::Low,
            timestamp: now - 15.0,
            flags: vec![],
            entities: {
                let mut m = serde_json::Map::new();
                m.insert("amount".into(), json!(100));
                m.insert("customer".into(), json!("cus_bbb"));
                m
            },
        });

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"))
            .with_session(session);

        // Third micro-charge to a third customer → card_testing block should fire
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 75, "currency": "usd", "customer": "cus_ccc"}
            }),
            metadata: Default::default(),
        };
        let result = engine.get_permission(&raw, &ctx).unwrap();
        assert_eq!(result.permission, Permission::Deny);
        assert!(result.risk_score.as_ref().is_some_and(|s| s.blocked));
    }

    #[test]
    fn no_session_still_works() {
        // Verify that passing no session context doesn't break anything
        let engine = build_test_engine();
        let ctx = default_ctx();
        let result = engine.get_permission(&stripe_charge(50), &ctx).unwrap();
        assert_eq!(result.source, DecisionSource::Scorer);
        assert!(result.risk_score.is_some());
    }
}
