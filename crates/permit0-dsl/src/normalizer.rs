#![forbid(unsafe_code)]

use std::collections::HashMap;

use permit0_normalize::{NormalizeCtx, NormalizeError, Normalizer};
use permit0_types::{ActionType, Entities, ExecutionMeta, NormAction, RawToolCall};

use crate::eval::entity::{extract_entities, EntityError};
use crate::eval::matcher::{eval_condition, MatchContext};
use crate::helpers::{build_helper_registry, HelperFn};
use crate::schema::normalizer::NormalizerDef;

/// A YAML-driven normalizer: parses a `NormalizerDef` and implements the
/// `Normalizer` trait from `permit0-normalize`.
pub struct DslNormalizer {
    def: NormalizerDef,
    helpers: HashMap<&'static str, (HelperFn, usize)>,
}

impl DslNormalizer {
    pub fn from_def(def: NormalizerDef) -> Self {
        Self {
            def,
            helpers: build_helper_registry(),
        }
    }

    /// Parse a YAML string into a DslNormalizer.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let def: NormalizerDef = serde_yaml::from_str(yaml)?;
        Ok(Self::from_def(def))
    }

    /// Access the underlying definition (for validation).
    pub fn def(&self) -> &NormalizerDef {
        &self.def
    }
}

impl Normalizer for DslNormalizer {
    fn id(&self) -> &str {
        &self.def.id
    }

    fn priority(&self) -> i32 {
        self.def.priority
    }

    fn matches(&self, raw: &RawToolCall) -> bool {
        let ctx = MatchContext {
            data: &raw.parameters,
            tool_name: Some(&raw.tool_name),
        };
        eval_condition(&self.def.match_expr, &ctx)
    }

    fn normalize(
        &self,
        raw: &RawToolCall,
        _ctx: &NormalizeCtx,
    ) -> Result<NormAction, NormalizeError> {
        let norm = &self.def.normalize;

        // Parse the action type from the YAML definition
        let action_type = ActionType::parse(&norm.action_type).map_err(|e| {
            NormalizeError::HelperFailed {
                helper: "action_type_parse".into(),
                reason: e.to_string(),
            }
        })?;

        // Extract entities
        let entity_map =
            extract_entities(&raw.parameters, &norm.entities, &self.helpers).map_err(
                |e| match e {
                    EntityError::MissingRequired(field) => NormalizeError::MissingRequiredField {
                        tool_name: raw.tool_name.clone(),
                        field,
                    },
                    EntityError::UnknownHelper(h) => NormalizeError::HelperFailed {
                        helper: h,
                        reason: "unknown helper".into(),
                    },
                    EntityError::ArityMismatch {
                        helper,
                        expected,
                        got,
                    } => NormalizeError::HelperFailed {
                        helper,
                        reason: format!("expected {expected} args, got {got}"),
                    },
                },
            )?;

        // Convert HashMap<String, Value> → Entities (serde_json::Map)
        let mut entities = Entities::new();
        for (k, v) in entity_map {
            entities.insert(k, v);
        }

        Ok(NormAction {
            action_type,
            channel: norm.channel.clone(),
            entities,
            execution: ExecutionMeta {
                surface_tool: raw.tool_name.clone(),
                surface_command: build_surface_command(raw),
            },
        })
    }
}

/// Build a human-readable surface command string for audit.
fn build_surface_command(raw: &RawToolCall) -> String {
    // For HTTP tools, try to build "METHOD URL"
    if let Some(method) = raw.parameters.get("method").and_then(|v| v.as_str()) {
        if let Some(url) = raw.parameters.get("url").and_then(|v| v.as_str()) {
            return format!("{method} {url}");
        }
    }
    // For shell tools, use the command
    if let Some(cmd) = raw.parameters.get("command").and_then(|v| v.as_str()) {
        return cmd.to_string();
    }
    // Fallback: tool name
    raw.tool_name.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const STRIPE_NORMALIZER_YAML: &str = r#"
permit0_pack: "permit0/stripe"
id: "stripe:charges.create"
priority: 100
match:
  all:
    - tool: http
    - method: POST
    - url:
        matches_url:
          host: api.stripe.com
          path: /v1/charges
normalize:
  action_type: "payments.charge"
  domain: "payments"
  verb: "charge"
  channel: "stripe"
  entities:
    amount:
      from: "body.amount"
      type: "number"
      required: true
    currency:
      from: "body.currency"
      type: "string"
      default: "usd"
    host:
      compute: "url_host"
      args:
        - "url"
"#;

    #[test]
    fn parse_yaml_normalizer() {
        let normalizer = DslNormalizer::from_yaml(STRIPE_NORMALIZER_YAML).unwrap();
        assert_eq!(normalizer.id(), "stripe:charges.create");
        assert_eq!(normalizer.priority(), 100);
    }

    #[test]
    fn matches_stripe_charge() {
        let normalizer = DslNormalizer::from_yaml(STRIPE_NORMALIZER_YAML).unwrap();
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 5000, "currency": "usd"}
            }),
            metadata: Default::default(),
        };
        assert!(normalizer.matches(&raw));
    }

    #[test]
    fn does_not_match_wrong_host() {
        let normalizer = DslNormalizer::from_yaml(STRIPE_NORMALIZER_YAML).unwrap();
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.evil.com/v1/charges",
                "body": {"amount": 5000}
            }),
            metadata: Default::default(),
        };
        assert!(!normalizer.matches(&raw));
    }

    #[test]
    fn normalize_stripe_charge() {
        let normalizer = DslNormalizer::from_yaml(STRIPE_NORMALIZER_YAML).unwrap();
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 5000, "currency": "usd"}
            }),
            metadata: Default::default(),
        };
        let ctx = NormalizeCtx::new().with_org_domain("acme.com");
        let norm = normalizer.normalize(&raw, &ctx).unwrap();

        assert_eq!(norm.action_type.as_action_str(), "payments.charge");
        assert_eq!(norm.channel, "stripe");
        assert_eq!(norm.entities["amount"], json!(5000));
        assert_eq!(norm.entities["currency"], json!("usd"));
        assert_eq!(norm.entities["host"], json!("api.stripe.com"));
        assert_eq!(norm.execution.surface_tool, "http");
        assert_eq!(
            norm.execution.surface_command,
            "POST https://api.stripe.com/v1/charges"
        );
    }

    #[test]
    fn normalize_missing_required_fails() {
        let normalizer = DslNormalizer::from_yaml(STRIPE_NORMALIZER_YAML).unwrap();
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"currency": "usd"}
            }),
            metadata: Default::default(),
        };
        let ctx = NormalizeCtx::new();
        let result = normalizer.normalize(&raw, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn default_entity_value() {
        let normalizer = DslNormalizer::from_yaml(STRIPE_NORMALIZER_YAML).unwrap();
        let raw = RawToolCall {
            tool_name: "http".into(),
            parameters: json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 1000}
            }),
            metadata: Default::default(),
        };
        let ctx = NormalizeCtx::new();
        let norm = normalizer.normalize(&raw, &ctx).unwrap();
        // currency should fall back to default "usd"
        assert_eq!(norm.entities["currency"], json!("usd"));
    }
}
