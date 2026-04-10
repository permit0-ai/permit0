#![forbid(unsafe_code)]

use serde::Deserialize;

/// A match/condition expression — recursive, composable with all/any/not.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ConditionExpr {
    All { all: Vec<ConditionExpr> },
    Any { any: Vec<ConditionExpr> },
    Not { not: Box<ConditionExpr> },
    /// A map of field → predicate pairs. All must be true (implicit AND).
    Leaf(std::collections::HashMap<String, Predicate>),
}

/// A predicate on a field value.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Predicate {
    /// Compound predicate: `field: { contains: ..., gt: ..., etc. }`
    /// Must be tried BEFORE Exact, since Value greedily matches maps.
    Compound(Box<PredicateOps>),
    /// Exact match: `field: value`
    Exact(serde_json::Value),
}

/// Compound predicate operations — all specified must be true.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PredicateOps {
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub starts_with: Option<String>,
    #[serde(default)]
    pub ends_with: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default, rename = "in")]
    pub in_list: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub not_in: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub exists: Option<bool>,
    #[serde(default)]
    pub gt: Option<f64>,
    #[serde(default)]
    pub gte: Option<f64>,
    #[serde(default)]
    pub lt: Option<f64>,
    #[serde(default)]
    pub lte: Option<f64>,
    #[serde(default)]
    pub not_empty: Option<bool>,
    #[serde(default)]
    pub matches_url: Option<UrlMatch>,
    #[serde(default)]
    pub any_match: Option<AnyMatch>,
    #[serde(default)]
    pub contains_any: Option<Vec<String>>,
    #[serde(default)]
    pub equals_ctx: Option<String>,
    #[serde(default)]
    pub in_set: Option<String>,
    #[serde(default)]
    pub not_in_set: Option<String>,
}

/// URL matching predicate.
#[derive(Debug, Clone, Deserialize)]
pub struct UrlMatch {
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub path_exact: bool,
}

/// Element-wise match on a list field.
#[derive(Debug, Clone, Deserialize)]
pub struct AnyMatch {
    pub field: String,
    pub value: serde_json::Value,
}
