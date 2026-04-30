// PyO3 generates unsafe FFI code internally — cannot use #![forbid(unsafe_code)]
#![doc = "Python bindings for the permit0 agent permission engine."]

use std::path::Path;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use permit0_agent::{AgentReviewer, CallbackLlmClient, LlmError};
use permit0_engine::{EngineBuilder, PermissionCtx, PermissionResult};
use permit0_normalize::NormalizeCtx;
use permit0_types::{Permission, RiskScore, Tier};

// ── Python wrapper types ──

/// Permission decision: "allow", "human", or "deny".
#[pyclass(name = "Permission", eq)]
#[derive(Clone, Debug, PartialEq)]
pub enum PyPermission {
    Allow,
    Human,
    Deny,
}

#[pymethods]
impl PyPermission {
    fn __repr__(&self) -> &'static str {
        match self {
            Self::Allow => "Permission.Allow",
            Self::Human => "Permission.Human",
            Self::Deny => "Permission.Deny",
        }
    }

    fn __str__(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Human => "human",
            Self::Deny => "deny",
        }
    }
}

impl From<Permission> for PyPermission {
    fn from(p: Permission) -> Self {
        match p {
            Permission::Allow => Self::Allow,
            Permission::HumanInTheLoop => Self::Human,
            Permission::Deny => Self::Deny,
        }
    }
}

/// Risk tier: Minimal, Low, Medium, High, Critical.
#[pyclass(name = "Tier", eq)]
#[derive(Clone, Debug, PartialEq)]
pub enum PyTier {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

#[pymethods]
impl PyTier {
    fn __repr__(&self) -> &'static str {
        match self {
            Self::Minimal => "Tier.Minimal",
            Self::Low => "Tier.Low",
            Self::Medium => "Tier.Medium",
            Self::High => "Tier.High",
            Self::Critical => "Tier.Critical",
        }
    }

    fn __str__(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl From<Tier> for PyTier {
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

/// Risk score output from the scoring pipeline.
#[pyclass(name = "RiskScore")]
#[derive(Clone, Debug)]
pub struct PyRiskScore {
    /// Raw score 0.0–1.0.
    #[pyo3(get)]
    pub raw: f64,
    /// Display score 0–100.
    #[pyo3(get)]
    pub score: u32,
    /// Risk tier.
    #[pyo3(get)]
    pub tier: PyTier,
    /// Flags that fired.
    #[pyo3(get)]
    pub flags: Vec<String>,
    /// Human-readable reason.
    #[pyo3(get)]
    pub reason: String,
    /// Whether a block rule fired.
    #[pyo3(get)]
    pub blocked: bool,
    /// Block reason, if any.
    #[pyo3(get)]
    pub block_reason: Option<String>,
}

#[pymethods]
impl PyRiskScore {
    fn __repr__(&self) -> String {
        format!(
            "RiskScore(raw={:.4}, score={}, tier={:?}, blocked={})",
            self.raw, self.score, self.tier, self.blocked
        )
    }
}

impl From<&RiskScore> for PyRiskScore {
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
#[pyclass(name = "NormAction")]
#[derive(Clone, Debug)]
pub struct PyNormAction {
    /// Action type string, e.g. "payment.charge".
    #[pyo3(get)]
    pub action_type: String,
    /// Channel/vendor, e.g. "stripe".
    #[pyo3(get)]
    pub channel: String,
    /// Semantic entities as a JSON string.
    #[pyo3(get)]
    pub entities_json: String,
    /// Norm hash hex (16 chars).
    #[pyo3(get)]
    pub norm_hash: String,
}

#[pymethods]
impl PyNormAction {
    fn __repr__(&self) -> String {
        format!(
            "NormAction(action_type='{}', channel='{}', norm_hash='{}')",
            self.action_type, self.channel, self.norm_hash
        )
    }

    /// Get entities as a Python dict.
    fn entities<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let val: serde_json::Value = serde_json::from_str(&self.entities_json)
            .map_err(|e| PyRuntimeError::new_err(format!("JSON parse error: {e}")))?;
        json_value_to_pydict(py, &val)
    }
}

/// Decision result from the engine.
#[pyclass(name = "DecisionResult")]
#[derive(Clone, Debug)]
pub struct PyDecisionResult {
    /// The permission decision.
    #[pyo3(get)]
    pub permission: PyPermission,
    /// The normalized action.
    #[pyo3(get)]
    pub norm_action: PyNormAction,
    /// Risk score (None if decision was from cache/list).
    #[pyo3(get)]
    pub risk_score: Option<PyRiskScore>,
    /// How the decision was reached.
    #[pyo3(get)]
    pub source: String,
}

#[pymethods]
impl PyDecisionResult {
    fn __repr__(&self) -> String {
        format!(
            "DecisionResult(permission={}, source='{}')",
            self.permission.__str__(),
            self.source
        )
    }
}

impl PyDecisionResult {
    fn from_result(r: &PermissionResult) -> Self {
        Self {
            permission: r.permission.into(),
            norm_action: PyNormAction {
                action_type: r.norm_action.action_type.as_action_str(),
                channel: r.norm_action.channel.clone(),
                entities_json: serde_json::to_string(&r.norm_action.entities).unwrap_or_default(),
                norm_hash: r.norm_action.norm_hash_hex(),
            },
            risk_score: r.risk_score.as_ref().map(PyRiskScore::from),
            source: format!("{:?}", r.source),
        }
    }
}

// ── Engine ──

/// The permit0 permission engine.
///
/// Use `Engine.from_packs()` or `EngineBuilder` to construct.
#[pyclass(name = "Engine")]
pub struct PyEngine {
    inner: permit0_engine::Engine,
}

#[pymethods]
impl PyEngine {
    /// Construct an engine from packs directory with optional profile.
    ///
    /// Args:
    ///     packs_dir: Path to packs directory (default: "packs")
    ///     profile: Optional profile name (e.g. "fintech")
    ///     profile_path: Optional path to profile YAML file
    ///     org_domain: Organization domain for normalization (default: "default.org")
    #[staticmethod]
    #[pyo3(signature = (packs_dir="packs", profile=None, profile_path=None))]
    fn from_packs(
        packs_dir: &str,
        profile: Option<&str>,
        profile_path: Option<&str>,
    ) -> PyResult<Self> {
        let config = load_config(profile, profile_path)?;
        let mut builder = EngineBuilder::new().with_config(config);

        let packs_path = Path::new(packs_dir);
        if packs_path.exists() {
            builder = install_packs_from_dir(builder, packs_path)?;
        }

        let engine = builder
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("engine build failed: {e}")))?;

        Ok(Self { inner: engine })
    }

    /// Evaluate a tool call and return a decision.
    ///
    /// Args:
    ///     tool_name: The tool name (e.g. "bash", "http")
    ///     parameters: Dict of parameters
    ///     org_domain: Organization domain (default: "default.org")
    ///
    /// Returns:
    ///     DecisionResult with permission, norm_action, risk_score, and source.
    #[pyo3(signature = (tool_name, parameters, org_domain="default.org"))]
    fn get_permission(
        &self,
        tool_name: &str,
        parameters: &Bound<'_, PyDict>,
        org_domain: &str,
    ) -> PyResult<PyDecisionResult> {
        let params_json = pydict_to_json_value(parameters)?;

        let tool_call = permit0_types::RawToolCall {
            tool_name: tool_name.to_string(),
            parameters: params_json,
            metadata: Default::default(),
        };

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain));

        let result = self
            .inner
            .get_permission(&tool_call, &ctx)
            .map_err(|e| PyRuntimeError::new_err(format!("engine error: {e}")))?;

        Ok(PyDecisionResult::from_result(&result))
    }

    /// Check the permission for a tool call given as a JSON string.
    ///
    /// Convenience method for when you have raw JSON.
    #[pyo3(signature = (json_str, org_domain="default.org"))]
    fn check_json(&self, json_str: &str, org_domain: &str) -> PyResult<PyDecisionResult> {
        let tool_call: permit0_types::RawToolCall = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("invalid JSON: {e}")))?;

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain));

        let result = self
            .inner
            .get_permission(&tool_call, &ctx)
            .map_err(|e| PyRuntimeError::new_err(format!("engine error: {e}")))?;

        Ok(PyDecisionResult::from_result(&result))
    }

    /// Evaluate a tool call with session context for cumulative risk detection.
    ///
    /// After the check, the result is automatically pushed into the session
    /// so subsequent calls see the full history.
    #[pyo3(signature = (session, tool_name, parameters, org_domain="default.org"))]
    fn check_with_session(
        &self,
        session: &mut PySession,
        tool_name: &str,
        parameters: &Bound<'_, PyDict>,
        org_domain: &str,
    ) -> PyResult<PyDecisionResult> {
        let params_json = pydict_to_json_value(parameters)?;

        let tool_call = permit0_types::RawToolCall {
            tool_name: tool_name.to_string(),
            parameters: params_json,
            metadata: Default::default(),
        };

        let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain(org_domain))
            .with_session(session.inner.clone());

        let result = self
            .inner
            .get_permission(&tool_call, &ctx)
            .map_err(|e| PyRuntimeError::new_err(format!("engine error: {e}")))?;

        // Auto-push result into session for subsequent calls
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        session.inner.push(permit0_session::ActionRecord {
            action_type: result.norm_action.action_type.as_action_str(),
            tier: result
                .risk_score
                .as_ref()
                .map(|s| s.tier)
                .unwrap_or(Tier::Minimal),
            flags: result
                .risk_score
                .as_ref()
                .map(|s| s.flags.clone())
                .unwrap_or_default(),
            timestamp: now,
            entities: result.norm_action.entities.clone(),
        });

        Ok(PyDecisionResult::from_result(&result))
    }

    fn __repr__(&self) -> &'static str {
        "Engine()"
    }
}

// ── EngineBuilder ──

/// Builder for constructing a configured Engine.
///
/// Example:
///     builder = EngineBuilder()
///     builder.install_normalizer_yaml(yaml_str)
///     builder.install_risk_rule_yaml(yaml_str)
///     engine = builder.build()
#[pyclass(name = "EngineBuilder")]
pub struct PyEngineBuilder {
    inner: Option<EngineBuilder>,
}

#[pymethods]
impl PyEngineBuilder {
    #[new]
    fn new() -> Self {
        Self {
            inner: Some(EngineBuilder::new()),
        }
    }

    /// Install a YAML normalizer definition.
    fn install_normalizer_yaml(&mut self, yaml: &str) -> PyResult<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("builder already consumed"))?;
        self.inner = Some(
            builder
                .install_normalizer_yaml(yaml)
                .map_err(|e| PyValueError::new_err(format!("normalizer error: {e}")))?,
        );
        Ok(())
    }

    /// Install a YAML risk rule definition.
    fn install_risk_rule_yaml(&mut self, yaml: &str) -> PyResult<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("builder already consumed"))?;
        self.inner = Some(
            builder
                .install_risk_rule_yaml(yaml)
                .map_err(|e| PyValueError::new_err(format!("risk rule error: {e}")))?,
        );
        Ok(())
    }

    /// Set an agent reviewer for MEDIUM-tier calls.
    ///
    /// The callback is a Python callable: `def review(prompt: str) -> str`
    /// It will be called by the Rust reviewer pipeline when a MEDIUM-tier
    /// action needs LLM review. The callback should call an LLM and return
    /// the raw text response.
    fn with_reviewer(&mut self, callback: PyObject) -> PyResult<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("builder already consumed"))?;

        // Wrap the Python callable in a Rust closure.
        // PyO3 handles re-entrant GIL acquisition on the same thread.
        let client = CallbackLlmClient::new(move |prompt: &str| {
            Python::with_gil(|py| {
                let result = callback
                    .call1(py, (prompt,))
                    .map_err(|e| LlmError::RequestFailed(format!("Python callback error: {e}")))?;
                result
                    .extract::<String>(py)
                    .map_err(|e| LlmError::ParseError(format!("expected str from callback: {e}")))
            })
        });

        let reviewer = AgentReviewer::new(Box::new(client));
        self.inner = Some(builder.with_reviewer(reviewer));
        Ok(())
    }

    /// Attach an audit bundle to this builder. The resulting engine will
    /// write signed audit entries for every decision.
    fn with_audit(&mut self, bundle: &PyAuditBundle) -> PyResult<()> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("builder already consumed"))?;
        self.inner = Some(builder.with_audit(bundle.sink.clone(), bundle.signer.clone()));
        Ok(())
    }

    /// Build the engine from the current configuration.
    fn build(&mut self) -> PyResult<PyEngine> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("builder already consumed"))?;
        let engine = builder
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("engine build failed: {e}")))?;
        Ok(PyEngine { inner: engine })
    }
}

// ── Session ──

/// Session context that accumulates action history for session-aware scoring.
///
/// Example:
///     session = Session("checkout-agent")
///     result = engine.check_with_session(session, "http", {...})
///     # session is auto-updated with the result
#[pyclass(name = "Session")]
pub struct PySession {
    inner: permit0_session::SessionContext,
}

#[pymethods]
impl PySession {
    #[new]
    fn new(session_id: &str) -> Self {
        Self {
            inner: permit0_session::SessionContext::new(session_id),
        }
    }

    /// Number of recorded actions.
    #[getter]
    fn len(&self) -> usize {
        self.inner.records.len()
    }

    /// The session ID.
    #[getter]
    fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    fn __repr__(&self) -> String {
        format!(
            "Session(id='{}', records={})",
            self.inner.session_id,
            self.inner.records.len()
        )
    }
}

// ── Audit Bundle ──

/// Export and verify signed audit bundles.
///
/// Usage:
///     bundle = AuditBundle()
///     # ... make engine calls ...
///     bundle.export_jsonl("audit.jsonl")
///     ok = AuditBundle.verify_jsonl("audit.jsonl", bundle.public_key)
#[pyclass(name = "AuditBundle")]
pub struct PyAuditBundle {
    sink: std::sync::Arc<permit0_store::audit::InMemoryAuditSink>,
    signer: std::sync::Arc<permit0_store::audit::Ed25519Signer>,
}

#[pymethods]
impl PyAuditBundle {
    #[new]
    fn new() -> Self {
        Self {
            sink: std::sync::Arc::new(permit0_store::audit::InMemoryAuditSink::new()),
            signer: std::sync::Arc::new(permit0_store::audit::Ed25519Signer::generate()),
        }
    }

    /// The ed25519 public key (hex) for this bundle's signer.
    #[getter]
    fn public_key(&self) -> String {
        use permit0_store::audit::AuditSigner;
        self.signer.public_key_hex()
    }

    /// Number of audit entries recorded.
    #[getter]
    fn entry_count(&self) -> usize {
        self.sink.all_entries().len()
    }

    /// Export all audit entries as JSONL to a file.
    fn export_jsonl(&self, path: &str) -> PyResult<()> {
        let entries = self.sink.all_entries();
        let mut file = std::fs::File::create(path)
            .map_err(|e| PyRuntimeError::new_err(format!("file create error: {e}")))?;
        permit0_store::audit::export_jsonl(&entries, &mut file)
            .map_err(|e| PyRuntimeError::new_err(format!("export error: {e}")))?;
        Ok(())
    }

    /// Verify chain integrity of a JSONL audit file.
    ///
    /// Returns (valid, entries_checked, failure_reason).
    #[staticmethod]
    fn verify_jsonl(path: &str, public_key_hex: &str) -> PyResult<(bool, u64, Option<String>)> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PyRuntimeError::new_err(format!("file read error: {e}")))?;

        let verifier = permit0_store::audit::Ed25519Verifier::from_hex(public_key_hex)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid public key: {e}")))?;

        let mut entries: Vec<permit0_store::audit::AuditEntry> = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: permit0_store::audit::AuditEntry = serde_json::from_str(line)
                .map_err(|e| PyRuntimeError::new_err(format!("JSON parse error: {e}")))?;
            entries.push(entry);
        }

        if entries.is_empty() {
            return Ok((true, 0, None));
        }

        // Verify each entry's hash and signature
        for (i, entry) in entries.iter().enumerate() {
            if !permit0_store::audit::chain::verify_entry_hash(entry) {
                return Ok((
                    false,
                    i as u64,
                    Some(format!("entry {} has invalid hash", entry.sequence)),
                ));
            }
            if !verifier.verify(&entry.entry_hash, &entry.signature) {
                return Ok((
                    false,
                    i as u64,
                    Some(format!("entry {} has invalid signature", entry.sequence)),
                ));
            }
        }

        // Verify chain links
        for window in entries.windows(2) {
            if !permit0_store::audit::chain::verify_chain_link(&window[0], &window[1]) {
                return Ok((
                    false,
                    window[1].sequence,
                    Some(format!(
                        "chain broken between {} and {}",
                        window[0].sequence, window[1].sequence
                    )),
                ));
            }
        }

        Ok((true, entries.len() as u64, None))
    }

    fn __repr__(&self) -> String {
        format!(
            "AuditBundle(entries={}, pubkey='{:.16}...')",
            self.entry_count(),
            self.public_key()
        )
    }
}

// ── Helpers ──

/// Convert a Python dict to serde_json::Value.
fn pydict_to_json_value(dict: &Bound<'_, PyDict>) -> PyResult<serde_json::Value> {
    // Serialize via Python's json module for robust conversion
    let json_mod = dict.py().import("json")?;
    let json_str: String = json_mod.call_method1("dumps", (dict,))?.extract()?;
    serde_json::from_str(&json_str)
        .map_err(|e| PyValueError::new_err(format!("JSON conversion error: {e}")))
}

/// Convert a serde_json::Value to a Python dict.
fn json_value_to_pydict<'py>(
    py: Python<'py>,
    val: &serde_json::Value,
) -> PyResult<Bound<'py, PyDict>> {
    let json_str = serde_json::to_string(val)
        .map_err(|e| PyRuntimeError::new_err(format!("JSON serialize error: {e}")))?;
    let json_mod = py.import("json")?;
    let result = json_mod.call_method1("loads", (json_str,))?;
    result
        .downcast::<PyDict>()
        .cloned()
        .map_err(|e| PyRuntimeError::new_err(format!("expected dict: {e}")))
}

/// Load scoring config with optional profile.
fn load_config(
    profile: Option<&str>,
    profile_path: Option<&str>,
) -> PyResult<permit0_scoring::ScoringConfig> {
    let profile_overrides = match (profile, profile_path) {
        (_, Some(path)) => {
            let yaml = std::fs::read_to_string(path).map_err(|e| {
                PyValueError::new_err(format!("failed to read profile {path}: {e}"))
            })?;
            let overrides: serde_json::Value = serde_yaml::from_str(&yaml)
                .map_err(|e| PyValueError::new_err(format!("failed to parse profile: {e}")))?;
            parse_profile_overrides(&overrides)?
        }
        (Some(name), None) => {
            let path = format!("profiles/{name}.profile.yaml");
            let yaml = std::fs::read_to_string(&path).map_err(|e| {
                PyValueError::new_err(format!("failed to read profile {path}: {e}"))
            })?;
            let overrides: serde_json::Value = serde_yaml::from_str(&yaml)
                .map_err(|e| PyValueError::new_err(format!("failed to parse profile: {e}")))?;
            parse_profile_overrides(&overrides)?
        }
        (None, None) => None,
    };

    let guardrails = permit0_scoring::Guardrails::default();
    permit0_scoring::ScoringConfig::from_layers(profile_overrides.as_ref(), None, &guardrails)
        .map_err(|e| PyRuntimeError::new_err(format!("guardrail violation: {e}")))
}

/// Parse profile YAML value into ProfileOverrides.
fn parse_profile_overrides(
    _val: &serde_json::Value,
) -> PyResult<Option<permit0_scoring::ProfileOverrides>> {
    // For now, use default overrides — full profile parsing mirrors engine_factory
    Ok(Some(permit0_scoring::ProfileOverrides::default()))
}

/// Install all packs from a directory into the builder.
fn install_packs_from_dir(mut builder: EngineBuilder, packs_dir: &Path) -> PyResult<EngineBuilder> {
    let entries = std::fs::read_dir(packs_dir)
        .map_err(|e| PyRuntimeError::new_err(format!("reading packs dir: {e}")))?;

    for entry in entries {
        let entry = entry.map_err(|e| PyRuntimeError::new_err(format!("reading entry: {e}")))?;
        if entry
            .file_type()
            .map_err(|e| PyRuntimeError::new_err(format!("file type: {e}")))?
            .is_dir()
        {
            let pack_dir = entry.path();

            // Install normalizers
            let norm_dir = pack_dir.join("normalizers");
            if norm_dir.exists() {
                for f in std::fs::read_dir(&norm_dir)
                    .map_err(|e| PyRuntimeError::new_err(format!("reading normalizers: {e}")))?
                {
                    let f = f.map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                    let path = f.path();
                    if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                        let yaml = std::fs::read_to_string(&path).map_err(|e| {
                            PyRuntimeError::new_err(format!("reading {}: {e}", path.display()))
                        })?;
                        builder = builder.install_normalizer_yaml(&yaml).map_err(|e| {
                            PyRuntimeError::new_err(format!("normalizer {}: {e}", path.display()))
                        })?;
                    }
                }
            }

            // Install risk rules
            let rules_dir = pack_dir.join("risk_rules");
            if rules_dir.exists() {
                for f in std::fs::read_dir(&rules_dir)
                    .map_err(|e| PyRuntimeError::new_err(format!("reading risk_rules: {e}")))?
                {
                    let f = f.map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
                    let path = f.path();
                    if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                        let yaml = std::fs::read_to_string(&path).map_err(|e| {
                            PyRuntimeError::new_err(format!("reading {}: {e}", path.display()))
                        })?;
                        builder = builder.install_risk_rule_yaml(&yaml).map_err(|e| {
                            PyRuntimeError::new_err(format!("risk rule {}: {e}", path.display()))
                        })?;
                    }
                }
            }
        }
    }

    Ok(builder)
}

// ── Module definition ──

/// permit0 — agent safety permission engine.
#[pymodule]
fn permit0(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPermission>()?;
    m.add_class::<PyTier>()?;
    m.add_class::<PyRiskScore>()?;
    m.add_class::<PyNormAction>()?;
    m.add_class::<PyDecisionResult>()?;
    m.add_class::<PyEngine>()?;
    m.add_class::<PyEngineBuilder>()?;
    m.add_class::<PySession>()?;
    m.add_class::<PyAuditBundle>()?;
    Ok(())
}
