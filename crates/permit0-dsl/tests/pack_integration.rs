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

    // Canonical flags: DESTRUCTION for rm -rf, PRIVILEGE for sudo
    assert!(template.flags.contains_key("DESTRUCTION"));
    assert!(template.flags.contains_key("PRIVILEGE"));
    // irreversibility upgraded by +6 (DESTRUCTION) and scope by +4 (both rules)
    assert_eq!(template.amplifiers.get("irreversibility"), Some(&12)); // 6 + 6
    assert_eq!(template.amplifiers.get("scope"), Some(&13)); // 5 + 4 + 4
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

    // High-value charge: amount upgraded by +6, destination by +5
    assert_eq!(template.amplifiers.get("amount"), Some(&18)); // 12 + 6
    assert_eq!(template.amplifiers.get("destination"), Some(&20)); // 15 + 5
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

    // Simulate session with 3 prior records (record_count > 2 fires)
    let session = json!({"record_count": 3, "daily_total": 500});
    execute_session_rules(&rule, &mut template, &session);

    // GOVERNANCE flag added, scope upgraded significantly
    assert!(template.flags.contains_key("GOVERNANCE"));
    assert_eq!(template.amplifiers.get("scope"), Some(&32)); // 8 + 24
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

    // Canonical flag: EXPOSURE for confidential subject
    assert!(template.flags.contains_key("EXPOSURE"));
    assert_eq!(template.amplifiers.get("sensitivity"), Some(&18)); // 8 + 10
}

// ── Filesystem Pack ──

const FS_READ_NORMALIZER: &str =
    include_str!("../../../packs/filesystem/normalizers/read.yaml");
const FS_READ_RISK: &str = include_str!("../../../packs/filesystem/risk_rules/read.yaml");

#[test]
fn fs_normalizes_read() {
    let n = load_normalizer(FS_READ_NORMALIZER);
    let raw = RawToolCall {
        tool_name: "file_read".into(),
        parameters: json!({"path": "/app/config.json"}),
        metadata: Default::default(),
    };
    assert!(n.matches(&raw));

    let ctx = NormalizeCtx::new();
    let norm = n.normalize(&raw, &ctx).unwrap();
    assert_eq!(norm.action_type.as_action_str(), "files.read");
}

#[test]
fn fs_risk_credentials_file() {
    let rule = load_risk_rule(FS_READ_RISK);
    let data = json!({"path": "/app/config/credentials.json"});
    let template = execute_risk_rules(&rule, &data, None);

    assert!(template.flags.contains_key("EXPOSURE"));
    assert!(template.flags.contains_key("GOVERNANCE"));
    assert!(template.flags.contains_key("PRIVILEGE"));
    assert_eq!(template.amplifiers.get("sensitivity"), Some(&31)); // 3 + 28
    assert_eq!(template.amplifiers.get("scope"), Some(&25)); // 3 + 22
    assert_eq!(template.amplifiers.get("destination"), Some(&20)); // 2 + 18
    assert!(!template.blocked);
}

#[test]
fn fs_risk_system_credential_gates() {
    let rule = load_risk_rule(FS_READ_RISK);
    let data = json!({"path": "/etc/shadow"});
    let template = execute_risk_rules(&rule, &data, None);

    assert!(template.blocked);
    assert_eq!(
        template.block_reason.as_deref(),
        Some("system_credential_access")
    );
}

// ── Bank Transfer Pack ──

const BANK_NORMALIZER: &str =
    include_str!("../../../packs/bank_transfer/normalizers/wire_transfer.yaml");
const BANK_RISK: &str = include_str!("../../../packs/bank_transfer/risk_rules/transfer.yaml");

#[test]
fn bank_normalizes_transfer() {
    let n = load_normalizer(BANK_NORMALIZER);
    let raw = RawToolCall {
        tool_name: "bank_transfer".into(),
        parameters: json!({
            "recipient_account": "GB82WEST12345698765432",
            "recipient_name": "Acme Supplies Ltd",
            "amount": 12000,
            "currency": "usd"
        }),
        metadata: Default::default(),
    };
    assert!(n.matches(&raw));

    let ctx = NormalizeCtx::new();
    let norm = n.normalize(&raw, &ctx).unwrap();
    assert_eq!(norm.action_type.as_action_str(), "payments.transfer");
    assert_eq!(norm.entities["amount"], json!(12000));
    assert_eq!(norm.entities["recipient"], json!("GB82WEST12345698765432"));
}

#[test]
fn bank_risk_medium_transfer() {
    let rule = load_risk_rule(BANK_RISK);
    let data = json!({"amount": 15000, "currency": "eur"});
    let template = execute_risk_rules(&rule, &data, None);

    // amount > 10000: upgrade amount +4, boundary +3
    assert_eq!(template.amplifiers.get("amount"), Some(&22)); // 18 + 4
    assert_eq!(template.amplifiers.get("boundary"), Some(&13)); // 10 + 3
    assert!(!template.blocked);
}

#[test]
fn bank_risk_extremely_large_gates() {
    let rule = load_risk_rule(BANK_RISK);
    let data = json!({"amount": 300000, "currency": "usd"});
    let template = execute_risk_rules(&rule, &data, None);

    assert!(template.blocked);
    assert_eq!(
        template.block_reason.as_deref(),
        Some("extremely_high_value_transfer")
    );
}

#[test]
fn bank_session_accumulation() {
    let rule = load_risk_rule(BANK_RISK);
    let data = json!({"amount": 8000, "currency": "usd"});
    let mut template = execute_risk_rules(&rule, &data, None);

    // Simulate session with daily_total > 15000
    let session = json!({"daily_total": 20000});
    execute_session_rules(&rule, &mut template, &session);

    assert!(template.flags.contains_key("GOVERNANCE"));
    assert_eq!(template.amplifiers.get("scope"), Some(&22)); // 10 + 12
    assert_eq!(template.amplifiers.get("amount"), Some(&28)); // 18 + 10
}
