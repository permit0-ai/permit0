//! Integration tests: load YAML packs, normalize raw tool calls, execute risk rules.

use permit0_dsl::normalizer::DslNormalizer;
use permit0_dsl::risk_executor::{execute_risk_rules, execute_session_rules};
use permit0_dsl::schema::risk_rule::RiskRuleDef;
use permit0_normalize::Normalizer;
use permit0_normalize::NormalizeCtx;
use permit0_types::RawToolCall;
use serde_json::json;

fn load_normalizer(yaml: &str) -> DslNormalizer {
    DslNormalizer::from_yaml(yaml).expect("valid YAML normalizer")
}

fn load_risk_rule(yaml: &str) -> RiskRuleDef {
    serde_yaml::from_str(yaml).expect("valid YAML risk rule")
}

// ── Bash Pack ──

const BASH_NORMALIZER: &str = include_str!("../../../packs/bash/normalizers/shell.yaml");
const BASH_RISK_RULES: &str = include_str!("../../../packs/bash/risk_rules/shell.yaml");

#[test]
fn bash_normalizes_simple_command() {
    let n = load_normalizer(BASH_NORMALIZER);
    let raw = RawToolCall {
        tool_name: "bash".into(),
        parameters: json!({"command": "ls -la /tmp"}),
        metadata: Default::default(),
    };
    assert!(n.matches(&raw));

    let ctx = NormalizeCtx::new();
    let norm = n.normalize(&raw, &ctx).unwrap();
    assert_eq!(norm.action_type.as_action_str(), "process.shell");
    assert_eq!(norm.channel, "bash");
    assert_eq!(norm.entities["command"], json!("ls -la /tmp"));
    assert_eq!(norm.entities["pipe_count"], json!(0));
}

#[test]
fn bash_risk_rm_rf() {
    let rule = load_risk_rule(BASH_RISK_RULES);
    let data = json!({"command": "sudo rm -rf /"});
    let template = execute_risk_rules(&rule, &data, Some("bash"));

    assert!(template.flags.contains_key("destructive_delete"));
    assert!(template.flags.contains_key("privilege_escalation"));
    // reversibility upgraded by 4: 5 + 4 = 9
    assert_eq!(template.amplifiers.get("reversibility"), Some(&9));
}

#[test]
fn bash_risk_device_write_gate() {
    let rule = load_risk_rule(BASH_RISK_RULES);
    let data = json!({"command": "echo data > /dev/sda"});
    let template = execute_risk_rules(&rule, &data, Some("bash"));

    assert!(template.blocked);
    assert_eq!(
        template.block_reason.as_deref(),
        Some("dangerous_device_write")
    );
}

// ── Stripe Pack ──

const STRIPE_CHARGE_NORMALIZER: &str =
    include_str!("../../../packs/stripe/normalizers/charges_create.yaml");
const STRIPE_CHARGE_RISK: &str = include_str!("../../../packs/stripe/risk_rules/charge.yaml");

#[test]
fn stripe_normalizes_charge() {
    let n = load_normalizer(STRIPE_CHARGE_NORMALIZER);
    let raw = RawToolCall {
        tool_name: "http".into(),
        parameters: json!({
            "method": "POST",
            "url": "https://api.stripe.com/v1/charges",
            "body": {"amount": 5000, "currency": "usd", "customer": "cus_123"}
        }),
        metadata: Default::default(),
    };
    assert!(n.matches(&raw));

    let ctx = NormalizeCtx::new().with_org_domain("acme.com");
    let norm = n.normalize(&raw, &ctx).unwrap();

    assert_eq!(norm.action_type.as_action_str(), "payments.charge");
    assert_eq!(norm.channel, "stripe");
    assert_eq!(norm.entities["amount"], json!(5000));
    assert_eq!(norm.entities["currency"], json!("usd"));
    assert_eq!(norm.entities["customer"], json!("cus_123"));
    assert_eq!(norm.entities["host"], json!("api.stripe.com"));
}

#[test]
fn stripe_risk_high_value() {
    let rule = load_risk_rule(STRIPE_CHARGE_RISK);
    let data = json!({"body": {"amount": 50000, "currency": "usd"}});
    let template = execute_risk_rules(&rule, &data, None);

    assert!(template.flags.contains_key("high_value"));
    assert_eq!(template.amplifiers.get("amount"), Some(&8)); // 5 + 3
    assert!(!template.blocked);
}

#[test]
fn stripe_risk_extremely_high_blocks() {
    let rule = load_risk_rule(STRIPE_CHARGE_RISK);
    let data = json!({"body": {"amount": 200000, "currency": "usd"}});
    let template = execute_risk_rules(&rule, &data, None);

    assert!(template.blocked);
}

#[test]
fn stripe_session_velocity() {
    let rule = load_risk_rule(STRIPE_CHARGE_RISK);
    let data = json!({"body": {"amount": 5000, "currency": "usd"}});
    let mut template = execute_risk_rules(&rule, &data, None);

    let session = json!({"daily_total": 60000});
    execute_session_rules(&rule, &mut template, &session);

    assert!(template.flags.contains_key("velocity_alert"));
    assert_eq!(template.amplifiers.get("scope"), Some(&5)); // 3 + 2
}

// ── Gmail Pack ──

const GMAIL_SEND_NORMALIZER: &str =
    include_str!("../../../packs/gmail/normalizers/send.yaml");
const GMAIL_SEND_RISK: &str = include_str!("../../../packs/gmail/risk_rules/send.yaml");

#[test]
fn gmail_normalizes_send() {
    let n = load_normalizer(GMAIL_SEND_NORMALIZER);
    let raw = RawToolCall {
        tool_name: "gmail_send".into(),
        parameters: json!({
            "to": "bob@external.com",
            "subject": "Hello",
            "body": "Test email"
        }),
        metadata: Default::default(),
    };
    assert!(n.matches(&raw));

    let ctx = NormalizeCtx::new().with_org_domain("acme.com");
    let norm = n.normalize(&raw, &ctx).unwrap();

    assert_eq!(norm.action_type.as_action_str(), "email.send");
    assert_eq!(norm.channel, "gmail");
    assert_eq!(norm.entities["to"], json!("bob@external.com"));
    assert_eq!(norm.entities["domain"], json!("external.com"));
}

#[test]
fn gmail_risk_confidential_subject() {
    let rule = load_risk_rule(GMAIL_SEND_RISK);
    let data = json!({
        "to": "bob@external.com",
        "subject": "confidential report Q4",
        "body": "Attached."
    });
    let template = execute_risk_rules(&rule, &data, None);

    assert!(template.flags.contains_key("sensitive_content"));
}
