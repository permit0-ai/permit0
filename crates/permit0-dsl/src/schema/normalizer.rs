#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::Deserialize;

use crate::schema::condition::ConditionExpr;

/// A normalizer YAML file — matches raw tool calls and produces NormActions.
#[derive(Debug, Clone, Deserialize)]
pub struct NormalizerDef {
    pub permit0_pack: String,
    pub id: String,
    pub priority: i32,
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub api_version: Option<ApiVersionDef>,
    #[serde(rename = "match")]
    pub match_expr: ConditionExpr,
    pub normalize: NormalizeDef,
}

/// API version handling for version-aware normalizers.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiVersionDef {
    pub vendor: String,
    pub range: String,
    pub detected_from: String,
    #[serde(default)]
    pub sunset: Option<String>,
}

/// The normalize section — what NormAction to produce.
#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeDef {
    pub action_type: String,
    pub domain: String,
    pub verb: String,
    pub channel: String,
    #[serde(default)]
    pub entities: HashMap<String, EntityDef>,
}

/// Definition of a single entity field.
#[derive(Debug, Clone, Deserialize)]
pub struct EntityDef {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default, rename = "type")]
    pub value_type: Option<String>,
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub optional: Option<bool>,
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    #[serde(default)]
    pub lowercase: Option<bool>,
    #[serde(default)]
    pub uppercase: Option<bool>,
    #[serde(default)]
    pub trim: Option<bool>,
    #[serde(default)]
    pub compute: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
}
