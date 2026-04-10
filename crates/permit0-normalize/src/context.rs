#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Org-provided context values available during normalization.
/// These are injected at engine construction time, not per-call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NormalizeCtx {
    /// Org domain (e.g. "acme.com") — used for internal/external classification.
    pub org_domain: Option<String>,
    /// Additional org-specific key-value pairs (e.g. stripe account ID).
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl NormalizeCtx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_org_domain(mut self, domain: impl Into<String>) -> Self {
        self.org_domain = Some(domain.into());
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}
