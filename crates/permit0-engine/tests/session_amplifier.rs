//! Integration demos for session-aware scoring.
//!
//! These tests build a real engine with the production email pack and exercise
//! the full pipeline (normalize → score → tier) through public API only. They
//! double as demo scenarios for the session amplifier.

use permit0_engine::{EngineBuilder, PermissionCtx};
use permit0_normalize::NormalizeCtx;
use permit0_session::{ActionRecord, SessionContext};
use permit0_test_utils::load_test_fixture;
use permit0_types::{RawToolCall, Tier};
use serde_json::json;

fn build_email_engine() -> permit0_engine::Engine {
    let gmail_norm = load_test_fixture("packs/permit0/email/normalizers/gmail/send.yaml");
    let outlook_norm = load_test_fixture("packs/permit0/email/normalizers/outlook/send.yaml");
    let email_risk = load_test_fixture("packs/permit0/email/risk_rules/send.yaml");
    EngineBuilder::new()
        .install_normalizer_yaml(&gmail_norm)
        .unwrap()
        .install_normalizer_yaml(&outlook_norm)
        .unwrap()
        .install_risk_rule_yaml(&email_risk)
        .unwrap()
        .build()
        .unwrap()
}

fn external_gmail_send(to: &str) -> RawToolCall {
    RawToolCall {
        tool_name: "gmail_send".into(),
        parameters: json!({
            "to": to,
            "subject": "monthly update",
            "body": "Hi,\nMonthly status.\n",
        }),
        metadata: Default::default(),
    }
}

fn internal_gmail_send(to: &str, subject: &str) -> RawToolCall {
    RawToolCall {
        tool_name: "gmail_send".into(),
        parameters: json!({
            "to": to,
            "subject": subject,
            "body": "hello",
        }),
        metadata: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn five_sends_in_ten_minutes_escalates_to_hitl() {
    use permit0_types::Permission;
    use std::time::{SystemTime, UNIX_EPOCH};

    let engine = build_email_engine();

    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("permit0.com"));
    let first = engine
        .get_permission(&internal_gmail_send("sfu@permit0.com", "hello 1"), &ctx)
        .unwrap();
    assert!(
        matches!(first.permission, Permission::Allow),
        "internal send with empty session should Allow, got {:?}",
        first.permission,
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut session = SessionContext::new("rate-limit-demo");
    for i in 0..5 {
        session.push(ActionRecord {
            action_type: "email.send".into(),
            tier: Tier::Low,
            flags: vec!["OUTBOUND".into(), "MUTATION".into()],
            timestamp: now - 60.0 * (5 - i) as f64,
            parameters: serde_json::Map::new(),
        });
    }

    let ctx_with_history =
        PermissionCtx::new(NormalizeCtx::new().with_org_domain("permit0.com"))
            .with_session(session);
    let sixth = engine
        .get_permission(
            &internal_gmail_send("sfu@permit0.com", "hello 6"),
            &ctx_with_history,
        )
        .unwrap();

    assert!(
        matches!(sixth.permission, Permission::HumanInTheLoop),
        "6th send within 10min should escalate to HITL, got {:?} (score={:?})",
        sixth.permission,
        sixth.risk_score,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_stays_in_hitl_after_compounding_session_amplifier() {
    use permit0_types::Permission;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Worst case: 5 prior High-tier email.send records with the rate-limit
    // rule's flags (GOVERNANCE etc.). Session amplifier maxes out (+30).
    // The 6th call must still be HumanInTheLoop, not Deny — otherwise the
    // rule pushes operators into a hard block they can't review.
    let engine = build_email_engine();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut session = SessionContext::new("compound-amp");
    for i in 0..5 {
        session.push(ActionRecord {
            action_type: "email.send".into(),
            tier: Tier::High,
            flags: vec![
                "OUTBOUND".into(),
                "MUTATION".into(),
                "EXPOSURE".into(),
                "GOVERNANCE".into(),
            ],
            timestamp: now - 60.0 * (5 - i) as f64,
            parameters: serde_json::Map::new(),
        });
    }

    let ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("permit0.com"))
        .with_session(session);
    let sixth = engine
        .get_permission(&internal_gmail_send("sfu@permit0.com", "hello 6"), &ctx)
        .unwrap();

    assert!(
        matches!(sixth.permission, Permission::HumanInTheLoop),
        "rate-limit rule must cap at HITL even under max session amplifier, \
         got {:?} (score={:?})",
        sixth.permission,
        sixth.risk_score,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_distinct_external_recipients_escalates_session_amplifier() {
    let engine = build_email_engine();

    let baseline_ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"));
    let baseline = engine
        .get_permission(&external_gmail_send("contact@vendor-x.com"), &baseline_ctx)
        .unwrap();

    // Replay 10 prior external sends, each to a different recipient domain.
    // Each prior send is High-tier (external-recipient rule fires in send.yaml)
    // with the four flags that rule adds. The built-in session_amplifier_score
    // contributes +8 per High record and +1 per distinct flag, capping at 30.
    let mut session = SessionContext::new("demo-bulk-send");
    let domains = [
        "vendor-a.com", "vendor-b.com", "vendor-c.com", "vendor-d.com",
        "vendor-e.com", "vendor-f.com", "vendor-g.com", "vendor-h.com",
        "vendor-i.com", "vendor-j.com",
    ];
    for (i, domain) in domains.iter().enumerate() {
        let mut params = serde_json::Map::new();
        params.insert(
            "to".into(),
            serde_json::Value::String(format!("contact{i}@{domain}")),
        );
        session.push(ActionRecord {
            action_type: "email.send".into(),
            tier: Tier::High,
            flags: vec![
                "OUTBOUND".into(),
                "MUTATION".into(),
                "GOVERNANCE".into(),
                "PRIVILEGE".into(),
            ],
            timestamp: 1_700_000_000.0 + i as f64,
            parameters: params,
        });
    }
    assert_eq!(session.records.len(), 10);

    let bulk_ctx = PermissionCtx::new(NormalizeCtx::new().with_org_domain("acme.com"))
        .with_session(session);
    let after_ten = engine
        .get_permission(&external_gmail_send("contact@vendor-x.com"), &bulk_ctx)
        .unwrap();

    let baseline_score = baseline.risk_score.as_ref().expect("baseline scored").raw;
    let bulk_score = after_ten.risk_score.as_ref().expect("bulk scored").raw;

    assert!(
        bulk_score > baseline_score,
        "session amplifier did not raise score: baseline={baseline_score:.3}, after_ten={bulk_score:.3}",
    );
    assert!(
        after_ten.risk_score.as_ref().unwrap().tier
            >= baseline.risk_score.as_ref().unwrap().tier,
        "tier regressed after 10 sends in session",
    );
}
