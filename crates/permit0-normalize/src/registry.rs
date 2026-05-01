#![forbid(unsafe_code)]

use std::sync::Arc;

use permit0_types::{NormAction, RawToolCall};

use crate::alias::AliasResolver;
use crate::context::NormalizeCtx;
use crate::error::{NormalizeError, RegistryError};
use crate::fallback::FallbackNormalizer;
use crate::traits::Normalizer;

/// Registry of normalizers, dispatched by priority (highest first).
///
/// Invariants:
/// - No two normalizers share the same priority (conflict detection at registration).
/// - A fallback normalizer (priority 0) always exists as the last resort.
/// - An alias resolver runs *before* normalizer dispatch and rewrites
///   `tool_name` for foreign tools that wrap permit0's canonical actions
///   under a different name (e.g. Google's official Gmail MCP).
pub struct NormalizerRegistry {
    /// Sorted by priority descending (highest first).
    by_priority: Vec<Arc<dyn Normalizer>>,
    /// Fallback normalizer for unknown tools (priority 0).
    fallback: Arc<dyn Normalizer>,
    /// Aliases applied before normalizer dispatch.
    aliases: AliasResolver,
}

impl NormalizerRegistry {
    /// Create a new registry with only the fallback normalizer.
    pub fn new() -> Self {
        Self {
            by_priority: Vec::new(),
            fallback: Arc::new(FallbackNormalizer),
            aliases: AliasResolver::new(),
        }
    }

    /// Create a registry with a custom fallback normalizer.
    pub fn with_fallback(fallback: Arc<dyn Normalizer>) -> Self {
        Self {
            by_priority: Vec::new(),
            fallback,
            aliases: AliasResolver::new(),
        }
    }

    /// Register a normalizer. Returns error if priority conflicts with an existing one.
    pub fn register(&mut self, normalizer: Arc<dyn Normalizer>) -> Result<(), RegistryError> {
        let new_priority = normalizer.priority();

        // Check for priority conflicts
        if let Some(existing) = self
            .by_priority
            .iter()
            .find(|n| n.priority() == new_priority)
        {
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

    /// Install a YAML alias document (`packs/<pack>/aliases.yaml`).
    ///
    /// Aliases let foreign tool names (e.g. Google's official Gmail MCP
    /// `create_label`) be rewritten to canonical names the registry's
    /// normalizers already match (`gmail_create_mailbox`). See
    /// [`AliasResolver`] for the YAML schema.
    pub fn install_aliases_yaml(&mut self, yaml: &str) -> Result<(), RegistryError> {
        let resolver = AliasResolver::from_yaml(yaml)?;
        self.aliases.merge(resolver)
    }

    /// Normalize a raw tool call by dispatching to the first matching normalizer.
    /// Falls back to the fallback normalizer if no registered normalizer matches.
    ///
    /// Alias resolution runs first: if the bare `tool_name` matches a
    /// registered alias and (for conditional aliases) the `when:` clause
    /// evaluates to a rewrite, the rewritten name is used for normalizer
    /// dispatch. The original tool name is preserved on the surface for
    /// audit (it ends up in `ExecutionMeta.surface_tool` via the matched
    /// normalizer's `surface_tool` slot, since we hand the rewritten
    /// `RawToolCall` to the normalizer).
    pub fn normalize(
        &self,
        raw: &RawToolCall,
        ctx: &NormalizeCtx,
    ) -> Result<NormAction, NormalizeError> {
        // Step 0: alias rewrite, if any.
        let resolved_name = self
            .aliases
            .resolve(&raw.tool_name, &raw.parameters)
            .map(str::to_owned);

        // If an alias rewrote the name, dispatch against a clone with the
        // canonical name. Otherwise the original raw call is used directly.
        let dispatch_target: std::borrow::Cow<'_, RawToolCall> = match resolved_name {
            Some(canonical) => std::borrow::Cow::Owned(RawToolCall {
                tool_name: canonical,
                parameters: raw.parameters.clone(),
                metadata: raw.metadata.clone(),
            }),
            None => std::borrow::Cow::Borrowed(raw),
        };

        for normalizer in &self.by_priority {
            if normalizer.matches(&dispatch_target) {
                return normalizer.normalize(&dispatch_target, ctx);
            }
        }

        // No registered normalizer matched — use fallback. Fallback uses
        // the ORIGINAL raw call so the audit log records the actual tool
        // name the agent invoked, not the (failed) alias guess.
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

    /// Number of registered aliases.
    pub fn alias_count(&self) -> usize {
        self.aliases.len()
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

    #[test]
    fn alias_rewrites_before_dispatch() {
        // Register a normalizer keyed on the canonical name, then alias
        // the foreign name to it. Confirms the rewrite happens before
        // normalizer matching.
        let mut reg = NormalizerRegistry::new();
        let email_create_mailbox = ActionType::parse("email.create_mailbox").unwrap();
        reg.register(Arc::new(MockNormalizer {
            id: "gmail_create_mailbox".into(),
            priority: 100,
            tool_match: "gmail_create_mailbox".into(),
            action_type: email_create_mailbox,
        }))
        .unwrap();

        reg.install_aliases_yaml(
            r#"
aliases:
  - tool: create_label
    rewrite_as: gmail_create_mailbox
"#,
        )
        .unwrap();
        assert_eq!(reg.alias_count(), 1);

        let ctx = NormalizeCtx::new();
        // Calling the foreign name routes through the alias to the
        // canonical normalizer.
        let action = reg.normalize(&make_raw("create_label"), &ctx).unwrap();
        assert_eq!(action.action_type, email_create_mailbox);
    }

    #[test]
    fn alias_unaliased_tool_falls_through_to_fallback() {
        let mut reg = NormalizerRegistry::new();
        reg.install_aliases_yaml(
            r#"
aliases:
  - tool: create_label
    rewrite_as: gmail_create_mailbox
"#,
        )
        .unwrap();

        let ctx = NormalizeCtx::new();
        let action = reg.normalize(&make_raw("totally_unknown"), &ctx).unwrap();
        // No alias, no normalizer → fallback fires.
        assert_eq!(action.action_type, ActionType::UNKNOWN);
    }

    #[test]
    fn alias_with_no_canonical_normalizer_falls_through_to_fallback() {
        // Alias rewrites to a name no normalizer knows. Should still
        // hit the fallback rather than panic.
        let mut reg = NormalizerRegistry::new();
        reg.install_aliases_yaml(
            r#"
aliases:
  - tool: foreign
    rewrite_as: nonexistent_canonical
"#,
        )
        .unwrap();

        let ctx = NormalizeCtx::new();
        let action = reg.normalize(&make_raw("foreign"), &ctx).unwrap();
        assert_eq!(action.action_type, ActionType::UNKNOWN);
    }

    #[test]
    fn conditional_alias_routes_by_param_value() {
        // Mirrors the real Gmail label_thread case: SPAM → mark_spam,
        // STARRED → flag, anything else → move.
        let mut reg = NormalizerRegistry::new();
        let mark_spam = ActionType::parse("email.mark_spam").unwrap();
        let flag = ActionType::parse("email.flag").unwrap();
        let move_action = ActionType::parse("email.move").unwrap();

        reg.register(Arc::new(MockNormalizer {
            id: "gmail_mark_spam".into(),
            priority: 100,
            tool_match: "gmail_mark_spam".into(),
            action_type: mark_spam,
        }))
        .unwrap();
        reg.register(Arc::new(MockNormalizer {
            id: "gmail_flag".into(),
            priority: 99,
            tool_match: "gmail_flag".into(),
            action_type: flag,
        }))
        .unwrap();
        reg.register(Arc::new(MockNormalizer {
            id: "gmail_move".into(),
            priority: 98,
            tool_match: "gmail_move".into(),
            action_type: move_action,
        }))
        .unwrap();

        reg.install_aliases_yaml(
            r#"
aliases:
  - tool: label_thread
    when:
      - if: { param: labelIds, contains: SPAM }
        rewrite_as: gmail_mark_spam
      - if: { param: labelIds, contains: STARRED }
        rewrite_as: gmail_flag
      - default: gmail_move
"#,
        )
        .unwrap();

        let ctx = NormalizeCtx::new();

        let spam_call = RawToolCall {
            tool_name: "label_thread".into(),
            parameters: serde_json::json!({"labelIds": ["SPAM"]}),
            metadata: serde_json::Map::new(),
        };
        assert_eq!(
            reg.normalize(&spam_call, &ctx).unwrap().action_type,
            mark_spam
        );

        let star_call = RawToolCall {
            tool_name: "label_thread".into(),
            parameters: serde_json::json!({"labelIds": ["STARRED"]}),
            metadata: serde_json::Map::new(),
        };
        assert_eq!(reg.normalize(&star_call, &ctx).unwrap().action_type, flag);

        let custom_call = RawToolCall {
            tool_name: "label_thread".into(),
            parameters: serde_json::json!({"labelIds": ["UserCustomLabel"]}),
            metadata: serde_json::Map::new(),
        };
        assert_eq!(
            reg.normalize(&custom_call, &ctx).unwrap().action_type,
            move_action
        );
    }
}
