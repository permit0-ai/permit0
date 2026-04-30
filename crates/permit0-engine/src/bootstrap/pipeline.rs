#![forbid(unsafe_code)]

use std::sync::Arc;

use permit0_agent::LlmClient;
use permit0_types::RawToolCall;

use super::proposal_store::ProposalStore;
use super::types::{BootstrapProposal, BootstrapResult, ProposalStatus};

/// The bootstrap pipeline: generates rule proposals for unknown action types.
pub struct BootstrapPipeline {
    llm_client: Box<dyn LlmClient>,
    proposal_store: Arc<dyn ProposalStore>,
}

impl BootstrapPipeline {
    pub fn new(llm_client: Box<dyn LlmClient>, proposal_store: Arc<dyn ProposalStore>) -> Self {
        Self {
            llm_client,
            proposal_store,
        }
    }

    /// Generate a bootstrap proposal for an unknown action type.
    ///
    /// Returns `AlreadyPending` if a proposal already exists for this action type.
    /// The proposal is NEVER auto-applied — it must be reviewed by a human.
    pub fn propose_rules(&self, action_type: &str, tool_call: &RawToolCall) -> BootstrapResult {
        // Check for existing pending proposal
        match self.proposal_store.get_pending_for_action(action_type) {
            Ok(Some(existing)) => {
                return BootstrapResult::AlreadyPending(existing.proposal_id);
            }
            Err(e) => {
                return BootstrapResult::ProposalFailed(format!(
                    "failed to check existing proposals: {e}"
                ));
            }
            Ok(None) => {}
        }

        // Build prompt
        let prompt = build_bootstrap_prompt(action_type, tool_call);

        // Call LLM
        let raw_response = match self.llm_client.review(&prompt) {
            Ok(resp) => resp,
            Err(e) => {
                return BootstrapResult::ProposalFailed(format!("LLM call failed: {e}"));
            }
        };

        // Parse response
        match parse_bootstrap_response(&raw_response) {
            Some((normalizer_yaml, risk_rule_yaml, reasoning)) => {
                let proposal = BootstrapProposal {
                    proposal_id: ulid::Ulid::new().to_string(),
                    action_type: action_type.into(),
                    raw_tool_call: serde_json::to_value(tool_call).unwrap_or_default(),
                    normalizer_yaml,
                    risk_rule_yaml,
                    reasoning,
                    status: ProposalStatus::Pending,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    reviewed_at: None,
                    reviewer: None,
                    review_notes: None,
                };

                if let Err(e) = self.proposal_store.save_proposal(proposal.clone()) {
                    return BootstrapResult::ProposalFailed(format!(
                        "failed to save proposal: {e}"
                    ));
                }

                BootstrapResult::ProposalCreated(Box::new(proposal))
            }
            None => BootstrapResult::ProposalFailed(
                "failed to parse LLM response into normalizer + risk rule YAML".into(),
            ),
        }
    }

    /// Approve a proposal — returns the YAML strings for installation.
    ///
    /// The caller (Engine or CLI) is responsible for installing the rules.
    pub fn approve_proposal(
        &self,
        proposal_id: &str,
        reviewer: &str,
        notes: Option<String>,
    ) -> Result<BootstrapProposal, String> {
        self.proposal_store.update_status(
            proposal_id,
            ProposalStatus::Approved,
            Some(reviewer.into()),
            notes,
        )?;
        self.proposal_store
            .get_proposal(proposal_id)?
            .ok_or_else(|| format!("proposal {proposal_id} not found after approval"))
    }

    /// Reject a proposal.
    pub fn reject_proposal(
        &self,
        proposal_id: &str,
        reviewer: &str,
        notes: Option<String>,
    ) -> Result<(), String> {
        self.proposal_store.update_status(
            proposal_id,
            ProposalStatus::Rejected,
            Some(reviewer.into()),
            notes,
        )
    }
}

/// Build the LLM prompt for bootstrapping rules.
fn build_bootstrap_prompt(action_type: &str, tool_call: &RawToolCall) -> String {
    let params_json = serde_json::to_string_pretty(&tool_call.parameters).unwrap_or_default();

    format!(
        r#"You are a security rule author for an AI agent permission system.

## Task
An unknown action type was encountered. Generate YAML rules for it.

## Unknown Action
- Tool name: {tool_name}
- Action type (detected): {action_type}
- Parameters:
{params_json}

## Output Format
Respond with EXACTLY this structure:

```normalizer
<normalizer YAML here>
```

```risk_rule
<risk rule YAML here>
```

```reasoning
<your reasoning here>
```

## Normalizer YAML format:
```yaml
tool_name: "<tool_name>"
action_type: "<domain>.<verb>"
channel: "<channel>"
entities:
  <entity_name>:
    path: "parameters.<path>"
    type: "string"
execution:
  surface_tool: "<tool_name>"
  surface_command: "parameters"
```

## Risk Rule YAML format:
```yaml
action_type: "<domain>.<verb>"
base_score: <0-100>
flags:
  - name: "<FLAG_NAME>"
    condition: "<condition expression>"
    weight: <integer>
    role: "amplifier"
```

## Guidelines
- Be conservative: prefer higher base_score for unknown actions
- Financial operations should have base_score >= 50
- Data exfiltration patterns should have high weights
- Include relevant flags for the action type
"#,
        tool_name = tool_call.tool_name,
    )
}

/// Parse the LLM response into (normalizer_yaml, risk_rule_yaml, reasoning).
fn parse_bootstrap_response(raw: &str) -> Option<(String, String, String)> {
    let normalizer = extract_fenced_block(raw, "normalizer")?;
    let risk_rule = extract_fenced_block(raw, "risk_rule")?;
    let reasoning = extract_fenced_block(raw, "reasoning").unwrap_or_default();
    Some((normalizer, risk_rule, reasoning))
}

/// Extract content between ```<tag> and ```.
fn extract_fenced_block(s: &str, tag: &str) -> Option<String> {
    let start_marker = format!("```{tag}");
    let start = s.find(&start_marker)?;
    let content_start = start + start_marker.len();
    // Skip to the next newline after the marker
    let content_start = s[content_start..].find('\n')? + content_start + 1;
    let end = s[content_start..].find("```")?;
    let content = s[content_start..content_start + end].trim();
    if content.is_empty() {
        None
    } else {
        Some(content.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::super::proposal_store::InMemoryProposalStore;
    use super::*;
    use permit0_agent::MockLlmClient;
    use serde_json::json;

    const MOCK_LLM_RESPONSE: &str = r#"Here are the proposed rules:

```normalizer
tool_name: "custom_api"
action_type: "custom.invoke"
channel: "api"
entities:
  endpoint:
    path: "parameters.url"
    type: "string"
```

```risk_rule
action_type: "custom.invoke"
base_score: 40
flags:
  - name: "EXTERNAL_API"
    condition: "true"
    weight: 10
    role: "amplifier"
```

```reasoning
This is a custom API call. Moderate risk due to external communication.
```
"#;

    fn make_tool_call() -> RawToolCall {
        RawToolCall {
            tool_name: "custom_api".into(),
            parameters: json!({"url": "https://api.example.com/action", "body": {"data": "test"}}),
            metadata: Default::default(),
        }
    }

    #[test]
    fn extract_fenced_blocks() {
        let normalizer = extract_fenced_block(MOCK_LLM_RESPONSE, "normalizer");
        assert!(normalizer.is_some());
        assert!(normalizer.unwrap().contains("custom_api"));

        let risk_rule = extract_fenced_block(MOCK_LLM_RESPONSE, "risk_rule");
        assert!(risk_rule.is_some());
        assert!(risk_rule.unwrap().contains("base_score"));

        let reasoning = extract_fenced_block(MOCK_LLM_RESPONSE, "reasoning");
        assert!(reasoning.is_some());
    }

    #[test]
    fn propose_rules_success() {
        let client = MockLlmClient::new(MOCK_LLM_RESPONSE);
        let store = Arc::new(InMemoryProposalStore::new());
        let pipeline = BootstrapPipeline::new(Box::new(client), store.clone());

        let result = pipeline.propose_rules("custom.invoke", &make_tool_call());
        match result {
            BootstrapResult::ProposalCreated(proposal) => {
                assert_eq!(proposal.action_type, "custom.invoke");
                assert_eq!(proposal.status, ProposalStatus::Pending);
                assert!(proposal.normalizer_yaml.contains("custom_api"));
                assert!(proposal.risk_rule_yaml.contains("base_score"));
            }
            other => panic!("expected ProposalCreated, got {other:?}"),
        }

        // Verify stored
        let pending = store.get_pending_for_action("custom.invoke").unwrap();
        assert!(pending.is_some());
    }

    #[test]
    fn propose_rules_already_pending() {
        let client = MockLlmClient::new(MOCK_LLM_RESPONSE);
        let store = Arc::new(InMemoryProposalStore::new());
        let pipeline = BootstrapPipeline::new(Box::new(client), store);

        // First proposal
        let result1 = pipeline.propose_rules("custom.invoke", &make_tool_call());
        assert!(matches!(result1, BootstrapResult::ProposalCreated(_)));

        // Second proposal for same action type
        let result2 = pipeline.propose_rules("custom.invoke", &make_tool_call());
        assert!(matches!(result2, BootstrapResult::AlreadyPending(_)));
    }

    #[test]
    fn propose_rules_llm_failure() {
        let client = MockLlmClient::garbage();
        let store = Arc::new(InMemoryProposalStore::new());
        let pipeline = BootstrapPipeline::new(Box::new(client), store);

        let result = pipeline.propose_rules("custom.invoke", &make_tool_call());
        assert!(matches!(result, BootstrapResult::ProposalFailed(_)));
    }

    #[test]
    fn approve_proposal_flow() {
        let client = MockLlmClient::new(MOCK_LLM_RESPONSE);
        let store = Arc::new(InMemoryProposalStore::new());
        let pipeline = BootstrapPipeline::new(Box::new(client), store.clone());

        let result = pipeline.propose_rules("custom.invoke", &make_tool_call());
        let proposal_id = match result {
            BootstrapResult::ProposalCreated(p) => p.proposal_id,
            _ => panic!("expected proposal"),
        };

        // Approve
        let approved = pipeline
            .approve_proposal(&proposal_id, "admin@example.com", Some("LGTM".into()))
            .unwrap();
        assert_eq!(approved.status, ProposalStatus::Approved);
        assert_eq!(approved.reviewer.as_deref(), Some("admin@example.com"));

        // No longer pending
        let pending = store.get_pending_for_action("custom.invoke").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn reject_proposal_flow() {
        let client = MockLlmClient::new(MOCK_LLM_RESPONSE);
        let store = Arc::new(InMemoryProposalStore::new());
        let pipeline = BootstrapPipeline::new(Box::new(client), store.clone());

        let result = pipeline.propose_rules("custom.invoke", &make_tool_call());
        let proposal_id = match result {
            BootstrapResult::ProposalCreated(p) => p.proposal_id,
            _ => panic!("expected proposal"),
        };

        pipeline
            .reject_proposal(&proposal_id, "admin@example.com", Some("Too broad".into()))
            .unwrap();

        let proposal = store.get_proposal(&proposal_id).unwrap().unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn no_auto_application_without_approval() {
        let client = MockLlmClient::new(MOCK_LLM_RESPONSE);
        let store = Arc::new(InMemoryProposalStore::new());
        let pipeline = BootstrapPipeline::new(Box::new(client), store);

        let result = pipeline.propose_rules("custom.invoke", &make_tool_call());
        match result {
            BootstrapResult::ProposalCreated(p) => {
                // Status is Pending, not Approved — rules are NOT active
                assert_eq!(p.status, ProposalStatus::Pending);
            }
            _ => panic!("expected proposal"),
        }
    }
}
