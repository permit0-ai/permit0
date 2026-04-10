#![forbid(unsafe_code)]

use serde::Deserialize;

/// Pack manifest — `pack.yaml` at the root of a pack directory.
#[derive(Debug, Clone, Deserialize)]
pub struct PackManifest {
    pub name: String,
    pub version: String,
    pub permit0_pack: String,
    pub vendor: String,
    #[serde(default)]
    pub description: Option<String>,
    pub normalizers: Vec<String>,
    pub risk_rules: Vec<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub min_engine_version: Option<String>,
}
