#![forbid(unsafe_code)]

use permit0_types::Tier;

use crate::context::SessionContext;
use crate::types::SessionFilter;

/// Result of a session block rule evaluation.
#[derive(Debug, Clone)]
pub struct SessionBlockResult {
    /// Whether the action should be blocked.
    pub blocked: bool,
    /// Which rule triggered the block (if any).
    pub rule_name: Option<String>,
    /// Human-readable reason.
    pub reason: Option<String>,
}

impl SessionBlockResult {
    fn pass() -> Self {
        Self {
            blocked: false,
            rule_name: None,
            reason: None,
        }
    }

    fn block(rule_name: &str, reason: &str) -> Self {
        Self {
            blocked: true,
            rule_name: Some(rule_name.into()),
            reason: Some(reason.into()),
        }
    }
}

/// Evaluate all built-in session block rules against the current action + session.
///
/// Returns the first block that fires, or a pass result.
pub fn evaluate_session_block_rules(
    session: &SessionContext,
    current_action_type: &str,
    current_entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    type BlockCheckFn = fn(
        &SessionContext,
        &str,
        &serde_json::Map<String, serde_json::Value>,
    ) -> SessionBlockResult;
    let checks: Vec<BlockCheckFn> = vec![
        privilege_escalation_then_exec,
        read_then_exfiltrate,
        bulk_external_send,
        cumulative_transfer_limit,
        card_testing,
        scatter_transfer,
        privilege_then_large_transfer,
    ];

    for check in checks {
        let result = check(session, current_action_type, current_entities);
        if result.blocked {
            return result;
        }
    }
    SessionBlockResult::pass()
}

/// Execution after privilege escalation.
fn privilege_escalation_then_exec(
    session: &SessionContext,
    current_action_type: &str,
    _entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    // Current action is shell or file write
    let exec_types = ["shell.execute", "files.write"];
    if !exec_types.contains(&current_action_type) {
        return SessionBlockResult::pass();
    }
    // Preceded by iam.assign_role within 5 actions
    if !session.preceded_by(&["iam.assign_role"], 5) {
        return SessionBlockResult::pass();
    }
    // Max tier >= HIGH
    if session.max_tier() < Tier::High {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "privilege_escalation_then_exec",
        "Execution after privilege escalation",
    )
}

/// Sensitive data read followed by external send.
fn read_then_exfiltrate(
    session: &SessionContext,
    current_action_type: &str,
    entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    // Current action is email.send or network.http_post
    let send_types = ["email.send", "network.http_post"];
    if !send_types.contains(&current_action_type) {
        return SessionBlockResult::pass();
    }
    // Check if recipient is external
    let is_external = entities
        .get("recipient_scope")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "external");
    if !is_external {
        return SessionBlockResult::pass();
    }
    // EXPOSURE in last 3 flags
    let recent_flags = session.flag_sequence(3);
    if !recent_flags.iter().any(|f| f == "EXPOSURE") {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "read_then_exfiltrate",
        "Sensitive data read followed by external send in same session",
    )
}

/// Email rate exceeds autonomous limit.
fn bulk_external_send(
    session: &SessionContext,
    current_action_type: &str,
    _entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    if current_action_type != "email.send" {
        return SessionBlockResult::pass();
    }
    let rate = session.rate_per_minute("email.send");
    if rate < 20.0 {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "bulk_external_send",
        "Email rate exceeds autonomous limit (>20/min)",
    )
}

/// Cumulative transfer amount exceeds session limit ($500k).
fn cumulative_transfer_limit(
    session: &SessionContext,
    current_action_type: &str,
    entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    if current_action_type != "payments.transfer" {
        return SessionBlockResult::pass();
    }
    let filter = SessionFilter::new().with_action_type("payments.transfer");
    let mut total = session.sum("amount", &filter);
    // Add current action's amount
    if let Some(current_amount) = entities.get("amount").and_then(|v| v.as_f64()) {
        total += current_amount;
    }
    if total < 500_000.0 {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "cumulative_transfer_limit",
        "Cumulative transfer amount exceeds $500k in session",
    )
}

/// Multiple micro-charges to different customers — possible card testing.
fn card_testing(
    session: &SessionContext,
    current_action_type: &str,
    entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    if current_action_type != "payments.charge" {
        return SessionBlockResult::pass();
    }
    // Count charges < $2 within 10 minutes (including current)
    let filter = SessionFilter::new()
        .with_action_type("payments.charge")
        .with_within_minutes(10);
    let matching = session.filter_records(&filter);
    let mut micro_charges: Vec<&serde_json::Map<String, serde_json::Value>> = matching
        .iter()
        .filter(|r| {
            r.entities
                .get("amount")
                .and_then(|v| v.as_f64())
                .is_some_and(|a| a < 200.0) // $2.00 in cents
        })
        .map(|r| &r.entities)
        .collect();
    // Check if current is also a micro-charge
    let current_is_micro = entities
        .get("amount")
        .and_then(|v| v.as_f64())
        .is_some_and(|a| a < 200.0);
    if current_is_micro {
        micro_charges.push(entities);
    }
    if micro_charges.len() < 5 {
        return SessionBlockResult::pass();
    }
    // Check for distinct customers
    let mut customers: Vec<&serde_json::Value> = Vec::new();
    for ents in &micro_charges {
        if let Some(cust) = ents.get("customer") {
            if !customers.contains(&cust) {
                customers.push(cust);
            }
        }
    }
    if customers.len() < 5 {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "card_testing",
        "Multiple small charges to different customers — possible card testing",
    )
}

/// Dispersed transfers to many recipients.
fn scatter_transfer(
    session: &SessionContext,
    current_action_type: &str,
    entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    if current_action_type != "payments.transfer" {
        return SessionBlockResult::pass();
    }
    let filter = SessionFilter::new()
        .with_action_type("payments.transfer")
        .with_within_minutes(60);
    let mut recipients = session.distinct_values("recipient", &filter);
    // Add current recipient
    if let Some(recip) = entities.get("recipient") {
        if !recipients.contains(recip) {
            recipients.push(recip.clone());
        }
    }
    if recipients.len() < 6 {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "scatter_transfer",
        "Dispersed transfers to many recipients within 60 minutes",
    )
}

/// Large transfer following privilege escalation.
fn privilege_then_large_transfer(
    session: &SessionContext,
    current_action_type: &str,
    entities: &serde_json::Map<String, serde_json::Value>,
) -> SessionBlockResult {
    if current_action_type != "payments.transfer" {
        return SessionBlockResult::pass();
    }
    // Preceded by iam.assign_role within 5 actions
    if !session.preceded_by(&["iam.assign_role"], 5) {
        return SessionBlockResult::pass();
    }
    // Cumulative transfers >= $10k
    let filter = SessionFilter::new().with_action_type("payments.transfer");
    let mut total = session.sum("amount", &filter);
    if let Some(amt) = entities.get("amount").and_then(|v| v.as_f64()) {
        total += amt;
    }
    if total < 10_000.0 {
        return SessionBlockResult::pass();
    }
    SessionBlockResult::block(
        "privilege_then_large_transfer",
        "Large transfer following privilege escalation",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ActionRecord;
    use serde_json::json;

    fn base_ts() -> f64 {
        // Use current time so within_minutes filters work
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    fn make_record(
        action_type: &str,
        tier: Tier,
        ts: f64,
        flags: &[&str],
        entities: Vec<(&str, serde_json::Value)>,
    ) -> ActionRecord {
        let mut ents = serde_json::Map::new();
        for (k, v) in entities {
            ents.insert(k.into(), v);
        }
        ActionRecord {
            action_type: action_type.into(),
            tier,
            flags: flags.iter().map(|s| s.to_string()).collect(),
            timestamp: ts,
            entities: ents,
        }
    }

    #[test]
    fn privilege_escalation_then_exec_fires() {
        let ts = base_ts();
        let mut session = SessionContext::new("test");
        session.push(make_record("iam.assign_role", Tier::High, ts, &[], vec![]));
        session.push(make_record(
            "secrets.read",
            Tier::Medium,
            ts + 1.0,
            &[],
            vec![],
        ));

        let entities = serde_json::Map::new();
        let result = evaluate_session_block_rules(&session, "shell.execute", &entities);
        assert!(result.blocked);
        assert_eq!(
            result.rule_name.as_deref(),
            Some("privilege_escalation_then_exec")
        );
    }

    #[test]
    fn read_then_exfiltrate_fires() {
        let ts = base_ts();
        let mut session = SessionContext::new("test");
        session.push(make_record(
            "files.read",
            Tier::Low,
            ts,
            &["EXPOSURE"],
            vec![],
        ));

        let mut entities = serde_json::Map::new();
        entities.insert("recipient_scope".into(), json!("external"));
        let result = evaluate_session_block_rules(&session, "email.send", &entities);
        assert!(result.blocked);
        assert_eq!(result.rule_name.as_deref(), Some("read_then_exfiltrate"));
    }

    #[test]
    fn cumulative_transfer_limit_fires() {
        let ts = base_ts();
        let mut session = SessionContext::new("test");
        session.push(make_record(
            "payments.transfer",
            Tier::Medium,
            ts,
            &[],
            vec![("amount", json!(200000))],
        ));
        session.push(make_record(
            "payments.transfer",
            Tier::Medium,
            ts + 1.0,
            &[],
            vec![("amount", json!(200000))],
        ));

        // Current transfer of $150k would push total to $550k
        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(150000));
        let result = evaluate_session_block_rules(&session, "payments.transfer", &entities);
        assert!(result.blocked);
        assert_eq!(
            result.rule_name.as_deref(),
            Some("cumulative_transfer_limit")
        );
    }

    #[test]
    fn card_testing_fires() {
        let ts = base_ts();
        let mut session = SessionContext::new("test");
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts,
            &[],
            vec![("amount", json!(50)), ("customer", json!("cus_aaa"))],
        ));
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts + 1.0,
            &[],
            vec![("amount", json!(100)), ("customer", json!("cus_bbb"))],
        ));
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts + 2.0,
            &[],
            vec![("amount", json!(75)), ("customer", json!("cus_ccc"))],
        ));
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts + 3.0,
            &[],
            vec![("amount", json!(60)), ("customer", json!("cus_ddd"))],
        ));

        // Fifth micro-charge to a fifth distinct customer → block
        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(80));
        entities.insert("customer".into(), json!("cus_eee"));
        let result = evaluate_session_block_rules(&session, "payments.charge", &entities);
        assert!(result.blocked);
        assert_eq!(result.rule_name.as_deref(), Some("card_testing"));
    }

    #[test]
    fn scatter_transfer_fires() {
        let ts = base_ts();
        let mut session = SessionContext::new("test");
        for (i, recip) in ["bank_a", "bank_b", "bank_c", "bank_d", "bank_e"]
            .iter()
            .enumerate()
        {
            session.push(make_record(
                "payments.transfer",
                Tier::Medium,
                ts + i as f64,
                &[],
                vec![("recipient", json!(recip))],
            ));
        }

        // 6th distinct recipient
        let mut entities = serde_json::Map::new();
        entities.insert("recipient".into(), json!("bank_f"));
        let result = evaluate_session_block_rules(&session, "payments.transfer", &entities);
        assert!(result.blocked);
        assert_eq!(result.rule_name.as_deref(), Some("scatter_transfer"));
    }

    #[test]
    fn no_block_when_below_thresholds() {
        let ts = base_ts();
        let mut session = SessionContext::new("test");
        session.push(make_record(
            "payments.transfer",
            Tier::Medium,
            ts,
            &[],
            vec![("amount", json!(1000)), ("recipient", json!("bank_a"))],
        ));

        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(1000));
        entities.insert("recipient".into(), json!("bank_b"));
        let result = evaluate_session_block_rules(&session, "payments.transfer", &entities);
        assert!(!result.blocked);
    }

    #[test]
    fn worked_example_cumulative_transfer_escalation() {
        // §12 Worked Example: Cumulative Transfer Escalation
        let ts = base_ts();
        let mut session = SessionContext::new("treasury-daily");

        // Call 1: $50k — below threshold
        session.push(make_record(
            "payments.transfer",
            Tier::Medium,
            ts,
            &[],
            vec![("amount", json!(50000)), ("recipient", json!("bank_a"))],
        ));
        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(50000));
        let result = evaluate_session_block_rules(&session, "payments.transfer", &entities);
        assert!(!result.blocked);

        // Call 2: $100k — total $150k, still below $500k
        session.push(make_record(
            "payments.transfer",
            Tier::High,
            ts + 60.0,
            &[],
            vec![("amount", json!(100000)), ("recipient", json!("bank_b"))],
        ));
        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(100000));
        let result = evaluate_session_block_rules(&session, "payments.transfer", &entities);
        assert!(!result.blocked);

        // Call 3: $400k — total $550k, exceeds $500k
        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(400000));
        entities.insert("recipient".into(), json!("bank_c"));
        let result = evaluate_session_block_rules(&session, "payments.transfer", &entities);
        assert!(result.blocked);
        assert_eq!(
            result.rule_name.as_deref(),
            Some("cumulative_transfer_limit")
        );
    }

    #[test]
    fn worked_example_card_testing() {
        // §12 Worked Example: Card Testing Detection
        let ts = base_ts();
        let mut session = SessionContext::new("checkout-agent");

        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts,
            &[],
            vec![("amount", json!(50)), ("customer", json!("cus_aaa"))],
        ));
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts + 10.0,
            &[],
            vec![("amount", json!(100)), ("customer", json!("cus_bbb"))],
        ));
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts + 20.0,
            &[],
            vec![("amount", json!(75)), ("customer", json!("cus_ccc"))],
        ));
        session.push(make_record(
            "payments.charge",
            Tier::Low,
            ts + 30.0,
            &[],
            vec![("amount", json!(90)), ("customer", json!("cus_ddd"))],
        ));

        // Call 5: fifth micro-charge to distinct customer → block
        let mut entities = serde_json::Map::new();
        entities.insert("amount".into(), json!(60));
        entities.insert("customer".into(), json!("cus_eee"));
        let result = evaluate_session_block_rules(&session, "payments.charge", &entities);
        assert!(result.blocked);
        assert_eq!(result.rule_name.as_deref(), Some("card_testing"));
    }

    #[test]
    fn worked_example_read_then_exfiltrate() {
        // §12 Worked Example: Read-Then-Exfiltrate
        let ts = base_ts();
        let mut session = SessionContext::new("task-42");

        // Call 1: files.read with EXPOSURE flag
        session.push(make_record(
            "files.read",
            Tier::Low,
            ts,
            &["EXPOSURE", "MUTATION"],
            vec![("path", json!("/etc/credentials.json"))],
        ));

        // Call 2: email.send to external → should fire read_then_exfiltrate
        let mut entities = serde_json::Map::new();
        entities.insert("recipient_scope".into(), json!("external"));
        entities.insert("to".into(), json!("attacker@evil.com"));
        let result = evaluate_session_block_rules(&session, "email.send", &entities);
        assert!(result.blocked);
        assert_eq!(result.rule_name.as_deref(), Some("read_then_exfiltrate"));
    }
}
