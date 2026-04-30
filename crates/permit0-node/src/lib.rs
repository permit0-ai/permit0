// napi-rs generates unsafe FFI code internally — cannot use #![forbid(unsafe_code)]
#![doc = "TypeScript/Node.js bindings for the permit0 agent permission engine."]

use std::path::Path;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use permit0_engine::{EngineBuilder, PermissionCtx, PermissionResult};
use permit0_normalize::NormalizeCtx;
use permit0_types::{Permission, RiskScore, Tier};

// ── Enums as string constants ──

/// Permission decision values.
#[napi(string_enum)]
pub enum JsPermission {
    Allow,
    Human,
    Deny,
}

impl From<Permission> for JsPermission {
    fn from(p: Permission) -> Self {
        match p {
            Permission::Allow => Self::Allow,
            Permission::HumanInTheLoop => Self::Human,
            Permission::Deny => Self::Deny,
        }
    }
}

/// Risk tier values.
#[napi(string_enum)]
pub enum JsTier {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Tier> for JsTier {
    fn from(t: Tier) -> Self {
        match t {
            Tier::Minimal => Self::Minimal,
            Tier::Low => Self::Low,
            Tier::Medium => Self::Medium,
            Tier::High => Self::High,
            Tier::Critical => Self::Critical,
        }
    }
}

// ── Output structs ──

/// Risk score output from the scoring pipeline.
#[napi(object)]
pub struct JsRiskScore {
    /// Raw score 0.0–1.0.
    pub raw: f64,
    /// Display score 0–100.
    pub score: u32,
    /// Risk tier.
    pub tier: JsTier,
    /// Flags that fired.
    pub flags: Vec<String>,
    /// Human-readable reason.
    pub reason: String,
    /// Whether a block rule fired.
    pub blocked: bool,
    /// Block reason, if any.
    pub block_reason: Option<String>,
}

impl From<&RiskScore> for JsRiskScore {
    fn from(s: &RiskScore) -> Self {
        Self {
            raw: s.raw,
            score: s.score,
            tier: s.tier.into(),
            flags: s.flags.clone(),
            reason: s.reason.clone(),
            blocked: s.blocked,
            block_reason: s.block_reason.clone(),
        }
    }
}

/// Normalized action — the tool-agnostic representation.
#[napi(object)]
pub struct JsNormAction {
    /// Action type string, e.g. "payment.charge".
    pub action_type: String,
    /// Channel/vendor, e.g. "stripe".
    pub channel: String,
    /// Semantic entities as a JSON string.
    pub entities_json: String,
    /// Norm hash hex (16 chars).
    pub norm_hash: String,
}

/// Decision result from the engine.
#[napi(object)]
pub struct JsDecisionResult {
    /// The permission decision.
    pub permission: JsPermission,
    /// The normalized action.
    pub norm_action: JsNormAction,
    /// Risk score (None if decision was from cache/list).
    pub risk_score: Option<JsRiskScore>,
    /// How the decision was reached.
    pub source: String,
}

impl JsDecisionResult {
    fn from_result(r: &PermissionResult) -> Self {
        Self {
            permission: r.permission.into(),
            norm_action: JsNormAction {
                action_type: r.norm_action.action_type.as_action_str(),
                channel: r.norm_action.channel.clone(),
                entities_json: serde_json::to_string(&r.norm_action.entities)
                    .unwrap_or_default(),
                norm_hash: r.norm_action.norm_hash_hex(),
            },
            risk_score: r.risk_score.as_ref().map(JsRiskScore::from),
            source: format!("{:?}", r.source),
        }
    }
}

// ── Engine ──

/// The permit0 permission engine.
///
/// Use `Engine.fromPacks()` or `EngineBuilder` to construct.
#[napi]
pub struct Engine {
    inner: permit0_engine::Engine,
}

#[napi]
impl Engine {
    /// Construct an engine from a packs directory.
    ///
    /// @param packsDir - Path to packs directory (default: "packs")
    /// @param profilePath - Optional path to a profile YAML file
    #[napi(factory)]
    pub fn from_packs(
        packs_dir: Option<String>,
        profile_path: Option<String>,
    ) -> Result<Self> {
        let packs = packs_dir.as_deref().unwrap_or("packs");
        let config = load_config(profile_path.as_deref())?;
        let mut builder = EngineBuilder::new().with_config(config);

        let packs_path = Path::new(packs);
        if packs_path.exists() {
            builder = install_packs_from_dir(builder, packs_path)?;
        }

        let engine = builder
            .build()
            .map_err(|e| Error::from_reason(format!("engine build failed: {e}")))?;

        Ok(Self { inner: engine })
    }

    /// Evaluate a tool call and return a decision.
    ///
    /// @param toolName - The tool name (e.g. "bash", "http")
    /// @param parameters - Parameters object
    /// @param orgDomain - Organization domain (default: "default.org")
    #[napi]
    pub fn get_permission(
        &self,
        tool_name: String,
        parameters: serde_json::Value,
        org_domain: Option<String>,
    ) -> Result<JsDecisionResult> {
        let domain = org_domain.as_deref().unwrap_or("default.org");

        let tool_call = permit0_types::RawToolCall {
            tool_name,
            parameters,
            metadata: Default::default(),
        };

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(domain));

        let result = self
            .inner
            .get_permission(&tool_call, &ctx)
            .map_err(|e| Error::from_reason(format!("engine error: {e}")))?;

        Ok(JsDecisionResult::from_result(&result))
    }

    /// Check the permission for a tool call given as a JSON string.
    #[napi]
    pub fn check_json(
        &self,
        json_str: String,
        org_domain: Option<String>,
    ) -> Result<JsDecisionResult> {
        let domain = org_domain.as_deref().unwrap_or("default.org");

        let tool_call: permit0_types::RawToolCall = serde_json::from_str(&json_str)
            .map_err(|e| Error::from_reason(format!("invalid JSON: {e}")))?;

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(domain));

        let result = self
            .inner
            .get_permission(&tool_call, &ctx)
            .map_err(|e| Error::from_reason(format!("engine error: {e}")))?;

        Ok(JsDecisionResult::from_result(&result))
    }
}

// ── EngineBuilder ──

/// Builder for constructing a configured Engine.
#[napi]
pub struct JsEngineBuilder {
    inner: Option<EngineBuilder>,
}

#[napi]
impl JsEngineBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(EngineBuilder::new()),
        }
    }

    /// Install a YAML normalizer definition.
    #[napi]
    pub fn install_normalizer_yaml(&mut self, yaml: String) -> Result<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| Error::from_reason("builder already consumed"))?;
        self.inner = Some(
            builder
                .install_normalizer_yaml(&yaml)
                .map_err(|e| Error::from_reason(format!("normalizer error: {e}")))?,
        );
        Ok(())
    }

    /// Install a YAML risk rule definition.
    #[napi]
    pub fn install_risk_rule_yaml(&mut self, yaml: String) -> Result<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| Error::from_reason("builder already consumed"))?;
        self.inner = Some(
            builder
                .install_risk_rule_yaml(&yaml)
                .map_err(|e| Error::from_reason(format!("risk rule error: {e}")))?,
        );
        Ok(())
    }

    /// Build the engine from the current configuration.
    #[napi]
    pub fn build(&mut self) -> Result<Engine> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| Error::from_reason("builder already consumed"))?;
        let engine = builder
            .build()
            .map_err(|e| Error::from_reason(format!("engine build failed: {e}")))?;
        Ok(Engine { inner: engine })
    }
}

// ── Helpers ──

/// Load scoring config with optional profile path.
fn load_config(
    profile_path: Option<&str>,
) -> Result<permit0_scoring::ScoringConfig> {
    let profile_overrides = match profile_path {
        Some(path) => {
            let _yaml = std::fs::read_to_string(path)
                .map_err(|e| Error::from_reason(format!("failed to read profile {path}: {e}")))?;
            Some(permit0_scoring::ProfileOverrides::default())
        }
        None => None,
    };

    let guardrails = permit0_scoring::Guardrails::default();
    permit0_scoring::ScoringConfig::from_layers(profile_overrides.as_ref(), None, &guardrails)
        .map_err(|e| Error::from_reason(format!("guardrail violation: {e}")))
}

/// Install all packs from a directory into the builder.
fn install_packs_from_dir(
    mut builder: EngineBuilder,
    packs_dir: &Path,
) -> Result<EngineBuilder> {
    let entries = std::fs::read_dir(packs_dir)
        .map_err(|e| Error::from_reason(format!("reading packs dir: {e}")))?;

    for entry in entries {
        let entry = entry.map_err(|e| Error::from_reason(format!("reading entry: {e}")))?;
        if entry
            .file_type()
            .map_err(|e| Error::from_reason(format!("file type: {e}")))?
            .is_dir()
        {
            let pack_dir = entry.path();

            // Install normalizers
            let norm_dir = pack_dir.join("normalizers");
            if norm_dir.exists() {
                for f in std::fs::read_dir(&norm_dir)
                    .map_err(|e| Error::from_reason(format!("reading normalizers: {e}")))?
                {
                    let f = f.map_err(|e| Error::from_reason(e.to_string()))?;
                    let path = f.path();
                    if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                        let yaml = std::fs::read_to_string(&path).map_err(|e| {
                            Error::from_reason(format!("reading {}: {e}", path.display()))
                        })?;
                        builder = builder.install_normalizer_yaml(&yaml).map_err(|e| {
                            Error::from_reason(format!("normalizer {}: {e}", path.display()))
                        })?;
                    }
                }
            }

            // Install risk rules
            let rules_dir = pack_dir.join("risk_rules");
            if rules_dir.exists() {
                for f in std::fs::read_dir(&rules_dir)
                    .map_err(|e| Error::from_reason(format!("reading risk_rules: {e}")))?
                {
                    let f = f.map_err(|e| Error::from_reason(e.to_string()))?;
                    let path = f.path();
                    if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                        let yaml = std::fs::read_to_string(&path).map_err(|e| {
                            Error::from_reason(format!("reading {}: {e}", path.display()))
                        })?;
                        builder = builder.install_risk_rule_yaml(&yaml).map_err(|e| {
                            Error::from_reason(format!("risk rule {}: {e}", path.display()))
                        })?;
                    }
                }
            }
        }
    }

    Ok(builder)
}
