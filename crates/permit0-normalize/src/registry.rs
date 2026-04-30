#![forbid(unsafe_code)]

use std::sync::Arc;

use permit0_types::{NormAction, RawToolCall};

use crate::context::NormalizeCtx;
use crate::error::{NormalizeError, RegistryError};
use crate::fallback::FallbackNormalizer;
use crate::traits::Normalizer;

/// Registry of normalizers, dispatched by priority (highest first).
///
/// Invariants:
/// - No two normalizers share the same priority (conflict detection at registration).
/// - A fallback normalizer (priority 0) always exists as the last resort.
pub struct NormalizerRegistry {
    /// Sorted by priority descending (highest first).
    by_priority: Vec<Arc<dyn Normalizer>>,
    /// Fallback normalizer for unknown tools (priority 0).
    fallback: Arc<dyn Normalizer>,
}

impl NormalizerRegistry {
    /// Create a new registry with only the fallback normalizer.
    pub fn new() -> Self {
        Self {
            by_priority: Vec::new(),
            fallback: Arc::new(FallbackNormalizer),
        }
    }

    /// Create a registry with a custom fallback normalizer.
    pub fn with_fallback(fallback: Arc<dyn Normalizer>) -> Self {
        Self {
            by_priority: Vec::new(),
            fallback,
        }
    }

    /// Register a normalizer. Returns error if priority conflicts with an existing one.
    pub fn register(&mut self, normalizer: Arc<dyn Normalizer>) -> Result<(), RegistryError> {
        let new_priority = normalizer.priority();

        // Check for priority conflicts
        if let Some(existing) = self.by_priority.iter().find(|n| n.priority() == new_priority) {
            return Err(RegistryError::PriorityConflict {
                a: existing.id().to_string(),
                b: normalizer.id().to_string(),
                priority: new_priority,
            });
        }

        self.by_priority.push(normalizer);
        // Re-sort: highest priority first
        self.by_priority
            .sort_by_key(|n| std::cmp::Reverse(n.priority()));

        Ok(())
    }

    /// Normalize a raw tool call by dispatching to the first matching normalizer.
    /// Falls back to the fallback normalizer if no registered normalizer matches.
    pub fn normalize(
        &self,
        raw: &RawToolCall,
        ctx: &NormalizeCtx,
    ) -> Result<NormAction, NormalizeError> {
        for normalizer in &self.by_priority {
            if normalizer.matches(raw) {
                return normalizer.normalize(raw, ctx);
            }
        }

        // No registered normalizer matched — use fallback
        self.fallback.normalize(raw, ctx)
    }

    /// Number of registered normalizers (excluding fallback).
    pub fn len(&self) -> usize {
        self.by_priority.len()
    }

    /// Whether the registry has no registered normalizers (excluding fallback).
    pub fn is_empty(&self) -> bool {
        self.by_priority.is_empty()
    }
}

impl Default for NormalizerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permit0_types::{ActionType, Entities, ExecutionMeta};

    /// Test normalizer that matches a specific tool name.
    struct MockNormalizer {
        id: String,
        priority: i32,
        tool_match: String,
        action_type: ActionType,
    }

    impl Normalizer for MockNormalizer {
        fn id(&self) -> &str {
            &self.id
        }

        fn priority(&self) -> i32 {
            self.priority
        }

        fn matches(&self, raw: &RawToolCall) -> bool {
            raw.tool_name == self.tool_match
        }

        fn normalize(
            &self,
            raw: &RawToolCall,
            _ctx: &NormalizeCtx,
        ) -> Result<NormAction, NormalizeError> {
            Ok(NormAction {
                action_type: self.action_type,
                channel: "test".into(),
                entities: Entities::new(),
                execution: ExecutionMeta {
                    surface_tool: raw.tool_name.clone(),
                    surface_command: String::new(),
                },
            })
        }
    }

    fn make_raw(tool: &str) -> RawToolCall {
        RawToolCall {
            tool_name: tool.into(),
            parameters: serde_json::json!({}),
            metadata: serde_json::Map::new(),
        }
    }

    #[test]
    fn highest_priority_wins() {
        let mut reg = NormalizerRegistry::new();
        let email_send = ActionType::parse("email.send").unwrap();
        let payments_charge = ActionType::parse("payment.charge").unwrap();

        reg.register(Arc::new(MockNormalizer {
            id: "low".into(),
            priority: 10,
            tool_match: "http".into(),
            action_type: email_send,
        }))
        .unwrap();
        reg.register(Arc::new(MockNormalizer {
            id: "high".into(),
            priority: 100,
            tool_match: "http".into(),
            action_type: payments_charge,
        }))
        .unwrap();

        let ctx = NormalizeCtx::new();
        let action = reg.normalize(&make_raw("http"), &ctx).unwrap();
        assert_eq!(action.action_type, payments_charge);
    }

    #[test]
    fn priority_conflict_detected() {
        let mut reg = NormalizerRegistry::new();
        let email_send = ActionType::parse("email.send").unwrap();

        reg.register(Arc::new(MockNormalizer {
            id: "first".into(),
            priority: 50,
            tool_match: "a".into(),
            action_type: email_send,
        }))
        .unwrap();

        let result = reg.register(Arc::new(MockNormalizer {
            id: "second".into(),
            priority: 50,
            tool_match: "b".into(),
            action_type: email_send,
        }));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("priority conflict"));
    }

    #[test]
    fn fallback_on_no_match() {
        let reg = NormalizerRegistry::new();
        let ctx = NormalizeCtx::new();
        let action = reg.normalize(&make_raw("unknown_tool"), &ctx).unwrap();
        assert_eq!(action.action_type, ActionType::UNKNOWN);
    }

    #[test]
    fn first_matching_normalizer_wins() {
        let mut reg = NormalizerRegistry::new();
        let payments_charge = ActionType::parse("payment.charge").unwrap();
        let network_http_post = ActionType::parse("network.post").unwrap();

        reg.register(Arc::new(MockNormalizer {
            id: "stripe".into(),
            priority: 100,
            tool_match: "http".into(),
            action_type: payments_charge,
        }))
        .unwrap();
        reg.register(Arc::new(MockNormalizer {
            id: "generic_http".into(),
            priority: 10,
            tool_match: "http".into(),
            action_type: network_http_post,
        }))
        .unwrap();

        let ctx = NormalizeCtx::new();
        let action = reg.normalize(&make_raw("http"), &ctx).unwrap();
        assert_eq!(action.action_type, payments_charge);
    }

    #[test]
    fn non_matching_normalizer_skipped() {
        let mut reg = NormalizerRegistry::new();
        let payments_charge = ActionType::parse("payment.charge").unwrap();

        reg.register(Arc::new(MockNormalizer {
            id: "stripe".into(),
            priority: 100,
            tool_match: "stripe_api".into(),
            action_type: payments_charge,
        }))
        .unwrap();

        let ctx = NormalizeCtx::new();
        let action = reg.normalize(&make_raw("bash"), &ctx).unwrap();
        assert_eq!(action.action_type, ActionType::UNKNOWN);
    }

    #[test]
    fn registry_len() {
        let mut reg = NormalizerRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());

        reg.register(Arc::new(MockNormalizer {
            id: "a".into(),
            priority: 10,
            tool_match: "a".into(),
            action_type: ActionType::UNKNOWN,
        }))
        .unwrap();

        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }
}
