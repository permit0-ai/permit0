#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use permit0_token::{
    BiscuitTokenProvider, HUMAN_TTL_SECS, IssuedBy, SCORER_TTL_SECS, Safeguard, TokenClaims,
    TokenScope, build_claims, safeguards_for_tier,
};
use permit0_types::{Entities, Tier};

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn basic_claims() -> TokenClaims {
    let now = now_secs();
    TokenClaims {
        action_type: "payments.charge".into(),
        scope: TokenScope {
            amount_ceiling: Some(10000.0),
            ..Default::default()
        },
        issued_by: IssuedBy::Scorer,
        risk_score: 15,
        risk_tier: Tier::Low,
        session_id: "sess-001".into(),
        safeguards: vec![],
        issued_at: now,
        expires_at: now + SCORER_TTL_SECS,
    }
}

#[test]
fn mint_verify_roundtrip() {
    let provider = BiscuitTokenProvider::new();
    let claims = basic_claims();

    let token = provider.mint(&claims).unwrap();
    assert!(!token.is_empty());

    let entities = Entities::new();
    let result = provider
        .verify(&token, "payments.charge", &entities)
        .unwrap();

    assert!(result.valid);
    assert_eq!(result.claims.action_type, "payments.charge");
    assert_eq!(result.claims.issued_by, IssuedBy::Scorer);
    assert_eq!(result.claims.risk_tier, Tier::Low);
    assert_eq!(result.claims.risk_score, 15);
    assert_eq!(result.claims.session_id, "sess-001");
}

#[test]
fn expired_token_rejected() {
    let provider = BiscuitTokenProvider::new();
    let now = now_secs();
    let claims = TokenClaims {
        action_type: "payments.charge".into(),
        scope: TokenScope::default(),
        issued_by: IssuedBy::Scorer,
        risk_score: 10,
        risk_tier: Tier::Minimal,
        session_id: "sess-002".into(),
        safeguards: vec![],
        issued_at: now - 600,  // issued 10 min ago
        expires_at: now - 300, // expired 5 min ago
    };

    let token = provider.mint(&claims).unwrap();
    let entities = Entities::new();
    let result = provider.verify(&token, "payments.charge", &entities);
    assert!(result.is_err());
}

#[test]
fn tampered_token_rejected() {
    let provider = BiscuitTokenProvider::new();
    let claims = basic_claims();
    let mut token = provider.mint(&claims).unwrap();

    // Tamper with the token bytes
    let mid = token.len() / 2;
    token[mid] ^= 0xFF;

    let entities = Entities::new();
    let result = provider.verify(&token, "payments.charge", &entities);
    assert!(result.is_err());
}

#[test]
fn wrong_action_type_rejected() {
    let provider = BiscuitTokenProvider::new();
    let claims = basic_claims();
    let token = provider.mint(&claims).unwrap();

    let entities = Entities::new();
    // Token is for payments.charge, but we verify against email.send
    let result = provider.verify(&token, "email.send", &entities);
    assert!(result.is_err());
}

#[test]
fn different_keypair_rejects() {
    let provider1 = BiscuitTokenProvider::new();
    let provider2 = BiscuitTokenProvider::new();
    let claims = basic_claims();
    let token = provider1.mint(&claims).unwrap();

    let entities = Entities::new();
    let result = provider2.verify(&token, "payments.charge", &entities);
    assert!(result.is_err());
}

#[test]
fn scope_amount_violation() {
    let provider = BiscuitTokenProvider::new();
    let claims = basic_claims(); // ceiling = 10000.0

    let token = provider.mint(&claims).unwrap();

    let mut entities = Entities::new();
    entities.insert("amount".into(), serde_json::json!(15000));

    let result = provider.verify(&token, "payments.charge", &entities);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("amount"));
}

#[test]
fn scope_amount_within_ceiling_allowed() {
    let provider = BiscuitTokenProvider::new();
    let claims = basic_claims(); // ceiling = 10000.0

    let token = provider.mint(&claims).unwrap();

    let mut entities = Entities::new();
    entities.insert("amount".into(), serde_json::json!(5000));

    let result = provider.verify(&token, "payments.charge", &entities);
    assert!(result.is_ok());
}

#[test]
fn scope_recipient_violation() {
    let provider = BiscuitTokenProvider::new();
    let now = now_secs();
    let claims = TokenClaims {
        action_type: "email.send".into(),
        scope: TokenScope {
            recipient: Some("alice@example.com".into()),
            ..Default::default()
        },
        issued_by: IssuedBy::Human,
        risk_score: 45,
        risk_tier: Tier::Medium,
        session_id: "sess-003".into(),
        safeguards: vec![Safeguard::LogEntities],
        issued_at: now,
        expires_at: now + HUMAN_TTL_SECS,
    };

    let token = provider.mint(&claims).unwrap();

    let mut entities = Entities::new();
    entities.insert("to".into(), serde_json::json!("bob@evil.com"));

    let result = provider.verify(&token, "email.send", &entities);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("recipient"));
}

#[test]
fn attenuated_token_narrower_scope_passes() {
    let provider = BiscuitTokenProvider::new();
    let claims = basic_claims(); // ceiling = 10000.0
    let token = provider.mint(&claims).unwrap();

    // Attenuate with no scope changes (just shorter TTL)
    let attenuated = provider
        .attenuate(&token, None, Some(Duration::from_secs(60)))
        .unwrap();

    let entities = Entities::new();
    let result = provider.verify(&attenuated, "payments.charge", &entities);
    assert!(result.is_ok());
}

#[test]
fn build_claims_helper_scorer_ttl() {
    let claims = build_claims(
        "payments.charge",
        TokenScope::default(),
        IssuedBy::Scorer,
        10,
        Tier::Low,
        "sess-100",
    );
    assert_eq!(claims.expires_at - claims.issued_at, SCORER_TTL_SECS);
    assert!(claims.safeguards.is_empty()); // Low tier has no safeguards
}

#[test]
fn build_claims_helper_human_ttl() {
    let claims = build_claims(
        "payments.charge",
        TokenScope::default(),
        IssuedBy::Human,
        50,
        Tier::High,
        "sess-200",
    );
    assert_eq!(claims.expires_at - claims.issued_at, HUMAN_TTL_SECS);
    // High tier safeguards
    assert!(claims.safeguards.contains(&Safeguard::LogEntities));
    assert!(claims.safeguards.contains(&Safeguard::LogBody));
    assert!(claims.safeguards.contains(&Safeguard::ConfirmBeforeExecute));
}

#[test]
fn safeguards_per_tier() {
    assert!(safeguards_for_tier(Tier::Minimal).is_empty());
    assert!(safeguards_for_tier(Tier::Low).is_empty());
    assert_eq!(
        safeguards_for_tier(Tier::Medium),
        vec![Safeguard::LogEntities]
    );
    assert_eq!(
        safeguards_for_tier(Tier::High),
        vec![
            Safeguard::LogEntities,
            Safeguard::LogBody,
            Safeguard::ConfirmBeforeExecute
        ]
    );
    assert!(safeguards_for_tier(Tier::Critical).is_empty());
}

#[test]
fn medium_tier_claims_have_safeguards() {
    let provider = BiscuitTokenProvider::new();
    let now = now_secs();
    let claims = TokenClaims {
        action_type: "payments.charge".into(),
        scope: TokenScope::default(),
        issued_by: IssuedBy::Human,
        risk_score: 45,
        risk_tier: Tier::Medium,
        session_id: "sess-med".into(),
        safeguards: safeguards_for_tier(Tier::Medium),
        issued_at: now,
        expires_at: now + HUMAN_TTL_SECS,
    };

    let token = provider.mint(&claims).unwrap();
    let entities = Entities::new();
    let result = provider
        .verify(&token, "payments.charge", &entities)
        .unwrap();

    assert_eq!(result.claims.safeguards, vec![Safeguard::LogEntities]);
}
