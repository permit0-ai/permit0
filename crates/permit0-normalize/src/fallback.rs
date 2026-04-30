#![forbid(unsafe_code)]

use permit0_types::{ActionType, Entities, ExecutionMeta, NormAction, RawToolCall};

use crate::context::NormalizeCtx;
use crate::error::NormalizeError;
use crate::traits::Normalizer;

/// Fallback normalizer for unrecognized tools.
/// Always matches, always at priority 0.
/// Maps to `unknown.unclassified` with the raw tool name as metadata.
pub struct FallbackNormalizer;

impl Normalizer for FallbackNormalizer {
    fn id(&self) -> &str {
        "fallback"
    }

    fn priority(&self) -> i32 {
        0
    }

    fn matches(&self, _raw: &RawToolCall) -> bool {
        true
    }

    fn normalize(
        &self,
        raw: &RawToolCall,
        _ctx: &NormalizeCtx,
    ) -> Result<NormAction, NormalizeError> {
        let mut entities = Entities::new();
        entities.insert(
            "raw_tool_name".into(),
            serde_json::Value::String(raw.tool_name.clone()),
        );

        Ok(NormAction {
            action_type: ActionType::UNKNOWN,
            channel: raw.tool_name.clone(),
            entities,
            execution: ExecutionMeta {
                surface_tool: raw.tool_name.clone(),
                surface_command: serde_json::to_string(&raw.parameters).unwrap_or_default(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_always_matches() {
        let f = FallbackNormalizer;
        let raw = RawToolCall {
            tool_name: "anything".into(),
            parameters: serde_json::json!({}),
            metadata: serde_json::Map::new(),
        };
        assert!(f.matches(&raw));
    }

    #[test]
    fn fallback_produces_unknown_action() {
        let f = FallbackNormalizer;
        let raw = RawToolCall {
            tool_name: "my_custom_tool".into(),
            parameters: serde_json::json!({"key": "value"}),
            metadata: serde_json::Map::new(),
        };
        let ctx = NormalizeCtx::new();
        let action = f.normalize(&raw, &ctx).unwrap();
        assert_eq!(action.action_type, ActionType::UNKNOWN);
        assert_eq!(action.domain(), permit0_types::Domain::Unknown);
        assert_eq!(action.channel, "my_custom_tool");
    }
}
