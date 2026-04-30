#![forbid(unsafe_code)]

use permit0_session::SessionContext;
use permit0_types::Tier;

use crate::client::LlmClient;
use crate::types::{
    ALWAYS_HUMAN_TYPES, AgentReviewResponse, DENY_CONFIDENCE_THRESHOLD,
    MEDIUM_SCORE_SKIP_THRESHOLD, ReviewInput, ReviewVerdict,
};

/// The agent-in-the-loop reviewer for MEDIUM-tier calls.
pub struct AgentReviewer {
    client: Box<dyn LlmClient>,
}

impl AgentReviewer {
    pub fn new(client: Box<dyn LlmClient>) -> Self {
        Self { client }
    }

    /// Review a MEDIUM-tier call. Returns HUMAN or DENY only.
    ///
    /// The reviewer is skipped (direct HUMAN) when:
    /// - Action type is in the always-human set
    /// - Score >= 52 (top of MEDIUM band)
    /// - Session already contains a blocked action
    pub fn handle_medium(
        &self,
        input: &ReviewInput,
        session: Option<&SessionContext>,
    ) -> AgentReviewResponse {
        // Check skip conditions
        if let Some(reason) = self.should_skip(input, session) {
            return AgentReviewResponse {
                verdict: ReviewVerdict::HumanInTheLoop,
                reason: reason.clone(),
                confidence: 1.0,
                escalate_reason: Some(reason),
            };
        }

        // Build prompt
        let prompt = build_prompt(input);

        // Call LLM
        let raw_response = match self.client.review(&prompt) {
            Ok(resp) => resp,
            Err(e) => {
                return AgentReviewResponse {
                    verdict: ReviewVerdict::HumanInTheLoop,
                    reason: format!("LLM error: {e}"),
                    confidence: 0.0,
                    escalate_reason: Some("LLM call failed".into()),
                };
            }
        };

        // Parse response
        let parsed = match parse_response(&raw_response) {
            Some(resp) => resp,
            None => {
                return AgentReviewResponse {
                    verdict: ReviewVerdict::HumanInTheLoop,
                    reason: "Failed to parse reviewer response".into(),
                    confidence: 0.0,
                    escalate_reason: Some("Parse failure — routing to human".into()),
                };
            }
        };

        // Confidence gate: deny requires >= 0.90
        if parsed.verdict == ReviewVerdict::Deny && parsed.confidence < DENY_CONFIDENCE_THRESHOLD {
            return AgentReviewResponse {
                verdict: ReviewVerdict::HumanInTheLoop,
                reason: parsed.reason,
                confidence: parsed.confidence,
                escalate_reason: Some(format!(
                    "Deny confidence {:.2} below threshold {DENY_CONFIDENCE_THRESHOLD}",
                    parsed.confidence
                )),
            };
        }

        parsed
    }

    /// Check if the reviewer should be skipped. Returns Some(reason) if yes.
    fn should_skip(&self, input: &ReviewInput, session: Option<&SessionContext>) -> Option<String> {
        let action_str = input.norm_action.action_type.as_action_str();

        // Always-human action types
        if ALWAYS_HUMAN_TYPES.contains(&action_str.as_str()) {
            return Some(format!("Action type '{action_str}' requires human review"));
        }

        // Score >= 52 (top of MEDIUM band)
        if input.risk_score.score >= MEDIUM_SCORE_SKIP_THRESHOLD {
            return Some(format!(
                "Score {} >= {MEDIUM_SCORE_SKIP_THRESHOLD} — too close to HIGH",
                input.risk_score.score
            ));
        }

        // Session contains a blocked action
        if let Some(session_ctx) = session {
            let has_blocked = session_ctx.records.iter().any(|r| r.tier >= Tier::Critical);
            if has_blocked {
                return Some("Session contains a previously blocked action".into());
            }
        }

        None
    }
}

/// Build the reviewer prompt from input context.
fn build_prompt(input: &ReviewInput) -> String {
    let action_str = input.norm_action.action_type.as_action_str();
    let channel = &input.norm_action.channel;
    let score = input.risk_score.score;
    let tier = &input.risk_score.tier;
    let flags: Vec<&str> = input.risk_score.flags.iter().map(|s| s.as_str()).collect();
    let reason = &input.risk_score.reason;

    let entities_json =
        serde_json::to_string_pretty(&input.norm_action.entities).unwrap_or_default();
    let raw_json = serde_json::to_string_pretty(&input.raw_tool_call).unwrap_or_default();

    let task_goal = input.task_goal.as_deref().unwrap_or("(not provided)");
    let session_summary = input
        .session_summary
        .as_deref()
        .unwrap_or("(no session history)");
    let org_policy = input
        .org_policy
        .as_deref()
        .unwrap_or("(no specific policy)");

    format!(
        r#"You are a security reviewer for an AI agent permission system.

## Your Role
You review MEDIUM-risk tool calls and decide: HUMAN (route to human for approval) or DENY (block).
You CANNOT approve actions. You CANNOT issue tokens. Your only outputs are Human or Deny.

## Hard Constraints
- Never allow if the action contradicts the stated task goal.
- Never allow if the action accesses data not mentioned in the task goal.
- Never allow financial transfers to recipients not named in the task goal.
- Always return Human if confidence < 0.7.
- Always return Human if the session shows read-then-send-externally.
- Never deny without a specific reason grounded in the data provided.
- DENY requires confidence >= 0.90 with a specific, grounded reason.

## Action Under Review
- Action Type: {action_str}
- Channel: {channel}
- Risk Score: {score}/100 (Tier: {tier})
- Risk Flags: {flags:?}
- Scoring Reason: {reason}

## Entities
{entities_json}

## Raw Tool Call
{raw_json}

## Task Goal
{task_goal}

## Session Summary
{session_summary}

## Organizational Policy
{org_policy}

## Response Format
Respond with ONLY a JSON object:
{{"verdict": "HumanInTheLoop" or "Deny", "reason": "<specific reason>", "confidence": <0.0-1.0>, "escalate_reason": "<why human needed>" or null}}
"#
    )
}

/// Parse the LLM response into an AgentReviewResponse.
fn parse_response(raw: &str) -> Option<AgentReviewResponse> {
    // Try to find JSON in the response (LLM might include extra text)
    let json_str = extract_json(raw)?;
    serde_json::from_str::<AgentReviewResponse>(&json_str).ok()
}

/// Extract the first JSON object from a string (handles LLM preamble/postamble).
fn extract_json(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let mut depth = 0;
    let mut end = start;
    for (i, ch) in s[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth == 0 && end > start {
        Some(s[start..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockLlmClient;
    use permit0_session::ActionRecord;
    use permit0_types::*;
    use serde_json::json;

    fn make_review_input(action_type: &str, score: u32) -> ReviewInput {
        ReviewInput {
            norm_action: NormAction {
                action_type: ActionType::parse(action_type).unwrap(),
                channel: "test".into(),
                entities: serde_json::Map::new(),
                execution: ExecutionMeta {
                    surface_tool: "test".into(),
                    surface_command: "test cmd".into(),
                },
            },
            risk_score: RiskScore {
                raw: score as f64 / 100.0,
                score,
                tier: Tier::Medium,
                blocked: false,
                flags: vec!["FINANCIAL".into()],
                block_reason: None,
                reason: "test reason".into(),
            },
            raw_tool_call: RawToolCall {
                tool_name: "test".into(),
                parameters: json!({}),
                metadata: Default::default(),
            },
            task_goal: Some("Transfer funds to vendor".into()),
            session_summary: None,
            org_policy: None,
        }
    }

    #[test]
    fn mock_llm_human_verdict() {
        let client = MockLlmClient::human("Needs human review for this transfer");
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("email.send", 40);

        let result = reviewer.handle_medium(&input, None);
        assert_eq!(result.verdict, ReviewVerdict::HumanInTheLoop);
    }

    #[test]
    fn mock_llm_deny_high_confidence() {
        let client = MockLlmClient::deny("Action contradicts task goal");
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("email.send", 40);

        let result = reviewer.handle_medium(&input, None);
        assert_eq!(result.verdict, ReviewVerdict::Deny);
        assert!(result.confidence >= DENY_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn deny_low_confidence_downgraded_to_human() {
        let client = MockLlmClient::deny_low_confidence("Suspicious but not certain");
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("email.send", 40);

        let result = reviewer.handle_medium(&input, None);
        assert_eq!(result.verdict, ReviewVerdict::HumanInTheLoop);
        assert!(result.escalate_reason.is_some());
    }

    #[test]
    fn parse_failure_routes_to_human() {
        let client = MockLlmClient::garbage();
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("email.send", 40);

        let result = reviewer.handle_medium(&input, None);
        assert_eq!(result.verdict, ReviewVerdict::HumanInTheLoop);
        assert!(result.reason.contains("parse"));
    }

    #[test]
    fn always_human_type_skips_reviewer() {
        let client = MockLlmClient::deny("Should not see this");
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("payment.charge", 40);

        let result = reviewer.handle_medium(&input, None);
        assert_eq!(result.verdict, ReviewVerdict::HumanInTheLoop);
        assert!(result.reason.contains("requires human review"));
    }

    #[test]
    fn score_above_52_skips_reviewer() {
        let client = MockLlmClient::deny("Should not see this");
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("email.send", 53);

        let result = reviewer.handle_medium(&input, None);
        assert_eq!(result.verdict, ReviewVerdict::HumanInTheLoop);
        assert!(result.reason.contains("too close to HIGH"));
    }

    #[test]
    fn session_with_blocked_action_skips_reviewer() {
        let client = MockLlmClient::deny("Should not see this");
        let reviewer = AgentReviewer::new(Box::new(client));
        let input = make_review_input("email.send", 40);

        let mut session = SessionContext::new("test");
        session.push(ActionRecord {
            action_type: "payment.transfer".into(),
            tier: Tier::Critical,
            flags: vec![],
            timestamp: 1_700_000_000.0,
            entities: serde_json::Map::new(),
        });

        let result = reviewer.handle_medium(&input, Some(&session));
        assert_eq!(result.verdict, ReviewVerdict::HumanInTheLoop);
        assert!(result.reason.contains("blocked action"));
    }

    #[test]
    fn reviewer_never_produces_allow() {
        // ReviewVerdict has no Allow variant — this is enforced at the type level.
        // Verify by matching all variants.
        let verdicts = [ReviewVerdict::HumanInTheLoop, ReviewVerdict::Deny];
        for v in &verdicts {
            match v {
                ReviewVerdict::HumanInTheLoop => {}
                ReviewVerdict::Deny => {} // No Allow variant exists — compilation would fail if one were added
                                          // without updating this test.
            }
        }
    }

    #[test]
    fn extract_json_from_preamble() {
        let raw = r#"Here is my analysis:
{"verdict":"HumanInTheLoop","reason":"test","confidence":0.5,"escalate_reason":null}
That's my verdict."#;
        let json = extract_json(raw).unwrap();
        let parsed: AgentReviewResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, ReviewVerdict::HumanInTheLoop);
    }

    #[test]
    fn extract_json_nested_braces() {
        let raw = r#"{"verdict":"Deny","reason":"contains {braces}","confidence":0.95,"escalate_reason":null}"#;
        let json = extract_json(raw).unwrap();
        let parsed: AgentReviewResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, ReviewVerdict::Deny);
    }

    #[test]
    fn all_always_human_types_skip() {
        let client = MockLlmClient::deny("Should be skipped");
        let reviewer = AgentReviewer::new(Box::new(client));

        for at in ALWAYS_HUMAN_TYPES {
            let input = make_review_input(at, 40);
            let result = reviewer.handle_medium(&input, None);
            assert_eq!(
                result.verdict,
                ReviewVerdict::HumanInTheLoop,
                "Expected HUMAN for always-human type {at}"
            );
        }
    }
}
