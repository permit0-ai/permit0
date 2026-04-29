#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::catalog::ActionType;

/// Opaque entity map — pack-defined fields.
pub type Entities = serde_json::Map<String, serde_json::Value>;

/// SHA-256 hash of the canonical JSON form.
pub type NormHash = [u8; 32];

/// A structured, tool-agnostic representation of what an action *means*.
/// This is the stable key used for risk rule lookup and caching.
///
/// The `action_type` field is a validated `ActionType` from the closed catalog.
/// Normalizers MUST map to a known `domain.verb` pair — they cannot invent new ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormAction {
    /// Validated action type from the catalog (e.g. payments.charge).
    pub action_type: ActionType,
    /// Channel/vendor, e.g. "gmail", "stripe".
    pub channel: String,
    /// Semantic parameters extracted by the normalizer.
    pub entities: Entities,
    /// Surface tool and raw command (for audit).
    pub execution: ExecutionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMeta {
    pub surface_tool: String,
    pub surface_command: String,
}

impl NormAction {
    /// Domain shorthand — delegates to `action_type.domain`.
    pub fn domain(&self) -> crate::catalog::Domain {
        self.action_type.domain
    }

    /// Verb shorthand — delegates to `action_type.verb`.
    pub fn verb(&self) -> crate::catalog::Verb {
        self.action_type.verb
    }

    /// Compute a stable hash for caching, allowlists, and denylists.
    ///
    /// Canonical JSON: sorted keys, no whitespace, null fields omitted.
    /// This hash MUST be byte-identical across engine versions and platforms.
    pub fn norm_hash(&self) -> NormHash {
        let canonical = canonical_json(self);
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hasher.finalize().into()
    }

    /// Display-friendly hex prefix of the norm_hash (16 chars).
    pub fn norm_hash_hex(&self) -> String {
        let hash = self.norm_hash();
        hex_prefix(&hash)
    }
}

/// Produce canonical JSON: keys sorted, no whitespace, deterministic.
fn canonical_json(action: &NormAction) -> String {
    // Build a sorted map to ensure deterministic key ordering.
    let mut map = serde_json::Map::new();
    map.insert(
        "action_type".into(),
        serde_json::Value::String(action.action_type.as_action_str()),
    );
    map.insert(
        "channel".into(),
        serde_json::Value::String(action.channel.clone()),
    );
    map.insert(
        "domain".into(),
        serde_json::Value::String(action.action_type.domain.to_string()),
    );

    // Sort entities by key
    let mut sorted_entities = serde_json::Map::new();
    let mut keys: Vec<&String> = action.entities.keys().collect();
    keys.sort();
    for key in keys {
        if let Some(val) = action.entities.get(key) {
            // Omit null values
            if !val.is_null() {
                sorted_entities.insert(key.clone(), val.clone());
            }
        }
    }
    map.insert("entities".into(), serde_json::Value::Object(sorted_entities));

    map.insert(
        "verb".into(),
        serde_json::Value::String(action.action_type.verb.to_string()),
    );

    serde_json::to_string(&serde_json::Value::Object(map))
        .expect("canonical JSON serialization should never fail")
}

/// First 16 hex characters of a hash.
fn hex_prefix(hash: &[u8; 32]) -> String {
    hash.iter()
        .take(8)
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Domain, Verb};

    fn test_action() -> NormAction {
        let mut entities = Entities::new();
        entities.insert("amount".into(), serde_json::json!(5000));
        entities.insert("currency".into(), serde_json::json!("usd"));

        NormAction {
            action_type: ActionType::new(Domain::Payment, Verb::Charge).unwrap(),
            channel: "stripe".into(),
            entities,
            execution: ExecutionMeta {
                surface_tool: "http".into(),
                surface_command: "POST /v1/charges".into(),
            },
        }
    }

    #[test]
    fn domain_and_verb_accessors() {
        let a = test_action();
        assert_eq!(a.domain(), Domain::Payment);
        assert_eq!(a.verb(), Verb::Charge);
    }

    #[test]
    fn norm_hash_is_deterministic() {
        let a = test_action();
        let h1 = a.norm_hash();
        let h2 = a.norm_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn norm_hash_ignores_execution_meta() {
        let mut a = test_action();
        let h1 = a.norm_hash();
        a.execution.surface_command = "something else".into();
        let h2 = a.norm_hash();
        assert_eq!(h1, h2, "execution meta should not affect norm_hash");
    }

    #[test]
    fn norm_hash_differs_on_entity_change() {
        let a = test_action();
        let h1 = a.norm_hash();

        let mut b = test_action();
        b.entities
            .insert("amount".into(), serde_json::json!(9999));
        let h2 = b.norm_hash();

        assert_ne!(h1, h2);
    }

    #[test]
    fn norm_hash_hex_is_16_chars() {
        let a = test_action();
        let hex = a.norm_hash_hex();
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let a = test_action();
        let json = canonical_json(&a);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = parsed.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn canonical_json_omits_null_entities() {
        let mut a = test_action();
        a.entities
            .insert("customer".into(), serde_json::Value::Null);
        let json = canonical_json(&a);
        assert!(!json.contains("customer"));
    }
}
