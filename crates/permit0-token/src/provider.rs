#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{Term, fact, string};
use biscuit_auth::{Authorizer, Biscuit, KeyPair};

use permit0_types::{Entities, Tier};

use crate::error::TokenError;
use crate::types::{
    HUMAN_TTL_SECS, IssuedBy, SCORER_TTL_SECS, Safeguard, TokenClaims, TokenScope,
    VerificationResult, safeguards_for_tier,
};

/// Biscuit-based capability token provider.
///
/// Handles minting, verifying, and attenuating permit0 capability tokens.
pub struct BiscuitTokenProvider {
    root_keypair: KeyPair,
}

impl Default for BiscuitTokenProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl BiscuitTokenProvider {
    /// Create a new provider with a fresh random keypair.
    pub fn new() -> Self {
        Self {
            root_keypair: KeyPair::new(),
        }
    }

    /// Create a provider from an existing keypair.
    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self {
            root_keypair: keypair,
        }
    }

    /// Create a provider from a private key bytes (32 bytes).
    pub fn from_private_key(bytes: &[u8]) -> Result<Self, TokenError> {
        let private = biscuit_auth::PrivateKey::from_bytes(bytes)
            .map_err(|e| TokenError::KeyError(e.to_string()))?;
        let keypair = KeyPair::from(&private);
        Ok(Self {
            root_keypair: keypair,
        })
    }

    /// Get the root public key (for verification by third parties).
    pub fn public_key(&self) -> biscuit_auth::PublicKey {
        self.root_keypair.public()
    }

    /// Mint a new capability token from claims.
    pub fn mint(&self, claims: &TokenClaims) -> Result<Vec<u8>, TokenError> {
        let mut builder = Biscuit::builder();

        // Core facts
        builder
            .add_fact(fact("action_type", &[string(&claims.action_type)]))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        builder
            .add_fact(fact(
                "issued_by",
                &[string(match claims.issued_by {
                    IssuedBy::Scorer => "scorer",
                    IssuedBy::Human => "human",
                })],
            ))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        builder
            .add_fact(fact("risk_tier", &[string(&claims.risk_tier.to_string())]))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        builder
            .add_fact(fact("session_id", &[string(&claims.session_id)]))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        // Risk score as integer
        builder
            .add_fact(fact(
                "risk_score",
                &[Term::Integer(claims.risk_score as i64)],
            ))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        // Timestamps (biscuit Term::Date takes u64 = unix seconds)
        builder
            .add_fact(fact("issued_at", &[Term::Date(claims.issued_at as u64)]))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        builder
            .add_fact(fact("expires_at", &[Term::Date(claims.expires_at as u64)]))
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        // Safeguards
        for sg in &claims.safeguards {
            let sg_str = match sg {
                Safeguard::LogEntities => "log_entities",
                Safeguard::LogBody => "log_body",
                Safeguard::ConfirmBeforeExecute => "confirm_before_execute",
            };
            builder
                .add_fact(fact("safeguard", &[string(sg_str)]))
                .map_err(|e| TokenError::Serialization(e.to_string()))?;
        }

        // Scope constraints
        if let Some(ref recipient) = claims.scope.recipient {
            builder
                .add_fact(fact("scope_recipient", &[string(recipient)]))
                .map_err(|e| TokenError::Serialization(e.to_string()))?;
        }
        if let Some(ref prefix) = claims.scope.path_prefix {
            builder
                .add_fact(fact("scope_path_prefix", &[string(prefix)]))
                .map_err(|e| TokenError::Serialization(e.to_string()))?;
        }
        if let Some(ceiling) = claims.scope.amount_ceiling {
            // Store as integer cents to avoid float issues in datalog
            let cents = (ceiling * 100.0) as i64;
            builder
                .add_fact(fact("scope_amount_ceiling", &[Term::Integer(cents)]))
                .map_err(|e| TokenError::Serialization(e.to_string()))?;
        }
        if let Some(ref env) = claims.scope.environment {
            builder
                .add_fact(fact("scope_environment", &[string(env)]))
                .map_err(|e| TokenError::Serialization(e.to_string()))?;
        }

        // Expiry check built into the authority block
        let mut expiry_params = HashMap::new();
        expiry_params.insert(
            "expires_at".to_string(),
            Term::Date(claims.expires_at as u64),
        );
        builder
            .add_code_with_params(
                "check if time($time), $time <= {expires_at}",
                expiry_params,
                HashMap::new(),
            )
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        let biscuit = builder
            .build(&self.root_keypair)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;

        biscuit
            .to_vec()
            .map_err(|e| TokenError::Serialization(e.to_string()))
    }

    /// Verify a token: check signature, expiry, action type, and scope constraints.
    ///
    /// `actual_entities` are the entities from the current request to verify against scope.
    pub fn verify(
        &self,
        token_bytes: &[u8],
        expected_action_type: &str,
        actual_entities: &Entities,
    ) -> Result<VerificationResult, TokenError> {
        let biscuit = Biscuit::from(token_bytes, self.root_keypair.public())
            .map_err(|_| TokenError::InvalidSignature)?;

        // Build authorizer
        let mut authorizer = Authorizer::new();

        // Provide current time
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        authorizer
            .add_fact(fact("time", &[Term::Date(now_secs)]))
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

        // Allow policy: token must have the right action type
        let mut params = HashMap::new();
        params.insert(
            "expected_action_type".to_string(),
            Term::Str(expected_action_type.to_string()),
        );
        authorizer
            .add_code_with_params(
                "allow if action_type({expected_action_type})",
                params,
                HashMap::new(),
            )
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

        // Add token and run authorization
        authorizer
            .add_token(&biscuit)
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

        authorizer.authorize().map_err(|e| {
            let msg = e.to_string();
            if msg.contains("time") || msg.contains("expir") {
                TokenError::Expired
            } else if msg.contains("action_type") {
                TokenError::ActionTypeMismatch {
                    expected: expected_action_type.to_string(),
                    actual: "unknown".to_string(),
                }
            } else {
                TokenError::VerificationFailed(msg)
            }
        })?;

        // Extract claims from authority facts
        let claims = self.extract_claims(&biscuit)?;

        // Verify scope constraints against actual entities
        self.verify_scope(&claims.scope, actual_entities)?;

        Ok(VerificationResult {
            claims,
            valid: true,
        })
    }

    /// Attenuate a token by appending a block that narrows scope or shortens TTL.
    pub fn attenuate(
        &self,
        token_bytes: &[u8],
        narrower_scope: Option<&TokenScope>,
        shorter_ttl: Option<Duration>,
    ) -> Result<Vec<u8>, TokenError> {
        let biscuit = Biscuit::from(token_bytes, self.root_keypair.public())
            .map_err(|_| TokenError::InvalidSignature)?;

        let mut block = biscuit_auth::builder::BlockBuilder::new();

        // Add narrower scope checks
        if let Some(scope) = narrower_scope {
            if let Some(ref recipient) = scope.recipient {
                let mut params = HashMap::new();
                params.insert("r".to_string(), Term::Str(recipient.clone()));
                block
                    .add_code_with_params("check if scope_recipient({r})", params, HashMap::new())
                    .map_err(|e| TokenError::AttenuationFailed(e.to_string()))?;
            }
            if let Some(ref prefix) = scope.path_prefix {
                let mut params = HashMap::new();
                params.insert("p".to_string(), Term::Str(prefix.clone()));
                block
                    .add_code_with_params(
                        "check if scope_path_prefix($prefix), {p}.starts_with($prefix)",
                        params,
                        HashMap::new(),
                    )
                    .map_err(|e| TokenError::AttenuationFailed(e.to_string()))?;
            }
            if let Some(ceiling) = scope.amount_ceiling {
                let cents = (ceiling * 100.0) as i64;
                let mut params = HashMap::new();
                params.insert("c".to_string(), Term::Integer(cents));
                block
                    .add_code_with_params(
                        "check if scope_amount_ceiling($ceil), {c} <= $ceil",
                        params,
                        HashMap::new(),
                    )
                    .map_err(|e| TokenError::AttenuationFailed(e.to_string()))?;
            }
        }

        // Shorter TTL: add a tighter expiry check
        if let Some(ttl) = shorter_ttl {
            let new_expiry_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + ttl.as_secs();
            let mut params = HashMap::new();
            params.insert("new_expiry".to_string(), Term::Date(new_expiry_secs));
            block
                .add_code_with_params(
                    "check if time($time), $time <= {new_expiry}",
                    params,
                    HashMap::new(),
                )
                .map_err(|e| TokenError::AttenuationFailed(e.to_string()))?;
        }

        let attenuated = biscuit
            .append(block)
            .map_err(|e| TokenError::AttenuationFailed(e.to_string()))?;

        attenuated
            .to_vec()
            .map_err(|e| TokenError::Serialization(e.to_string()))
    }

    /// Extract claims from a verified biscuit's authority facts.
    fn extract_claims(&self, biscuit: &Biscuit) -> Result<TokenClaims, TokenError> {
        let mut authorizer = biscuit
            .authorizer()
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

        // We need to provide time and a permissive policy to run the authorizer
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        authorizer
            .add_fact(fact("time", &[Term::Date(now_secs)]))
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;
        authorizer
            .add_code("allow if true")
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;
        authorizer
            .authorize()
            .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

        // Query facts
        let action_type =
            query_string_fact(&mut authorizer, "data($x) <- action_type($x)").unwrap_or_default();
        let issued_by_str =
            query_string_fact(&mut authorizer, "data($x) <- issued_by($x)").unwrap_or_default();
        let risk_tier_str =
            query_string_fact(&mut authorizer, "data($x) <- risk_tier($x)").unwrap_or_default();
        let session_id =
            query_string_fact(&mut authorizer, "data($x) <- session_id($x)").unwrap_or_default();

        let risk_score =
            query_int_fact(&mut authorizer, "data($x) <- risk_score($x)").unwrap_or(0) as u32;

        let issued_at = query_date_fact(&mut authorizer, "data($x) <- issued_at($x)").unwrap_or(0);
        let expires_at =
            query_date_fact(&mut authorizer, "data($x) <- expires_at($x)").unwrap_or(0);

        // Safeguards
        let safeguards = query_all_string_facts(&mut authorizer, "data($x) <- safeguard($x)")
            .into_iter()
            .filter_map(|s| match s.as_str() {
                "log_entities" => Some(Safeguard::LogEntities),
                "log_body" => Some(Safeguard::LogBody),
                "confirm_before_execute" => Some(Safeguard::ConfirmBeforeExecute),
                _ => None,
            })
            .collect();

        // Scope
        let recipient = query_string_fact(&mut authorizer, "data($x) <- scope_recipient($x)");
        let path_prefix = query_string_fact(&mut authorizer, "data($x) <- scope_path_prefix($x)");
        let amount_ceiling =
            query_int_fact(&mut authorizer, "data($x) <- scope_amount_ceiling($x)")
                .map(|cents| cents as f64 / 100.0);
        let environment = query_string_fact(&mut authorizer, "data($x) <- scope_environment($x)");

        let issued_by = match issued_by_str.as_str() {
            "human" => IssuedBy::Human,
            _ => IssuedBy::Scorer,
        };

        let risk_tier = match risk_tier_str.as_str() {
            "MINIMAL" => Tier::Minimal,
            "LOW" => Tier::Low,
            "MEDIUM" => Tier::Medium,
            "HIGH" => Tier::High,
            "CRITICAL" => Tier::Critical,
            _ => Tier::Critical,
        };

        Ok(TokenClaims {
            action_type,
            scope: TokenScope {
                recipient,
                path_prefix,
                amount_ceiling,
                environment,
            },
            issued_by,
            risk_score,
            risk_tier,
            session_id,
            safeguards,
            issued_at,
            expires_at,
        })
    }

    /// Verify scope constraints against actual entities.
    fn verify_scope(&self, scope: &TokenScope, entities: &Entities) -> Result<(), TokenError> {
        if let Some(ref expected_recipient) = scope.recipient {
            if let Some(actual) = entities.get("to").or_else(|| entities.get("recipient")) {
                if let Some(actual_str) = actual.as_str() {
                    if actual_str != expected_recipient {
                        return Err(TokenError::ScopeViolation(format!(
                            "recipient mismatch: expected {expected_recipient}, got {actual_str}"
                        )));
                    }
                }
            }
        }

        if let Some(ref prefix) = scope.path_prefix {
            if let Some(actual) = entities.get("path").or_else(|| entities.get("file_path")) {
                if let Some(actual_str) = actual.as_str() {
                    if !actual_str.starts_with(prefix.as_str()) {
                        return Err(TokenError::ScopeViolation(format!(
                            "path {actual_str} not under prefix {prefix}"
                        )));
                    }
                }
            }
        }

        if let Some(ceiling) = scope.amount_ceiling {
            if let Some(actual) = entities.get("amount") {
                let actual_amount = actual.as_f64().unwrap_or(0.0);
                if actual_amount > ceiling {
                    return Err(TokenError::ScopeViolation(format!(
                        "amount {actual_amount} exceeds ceiling {ceiling}"
                    )));
                }
            }
        }

        if let Some(ref expected_env) = scope.environment {
            if let Some(actual) = entities.get("environment") {
                if let Some(actual_str) = actual.as_str() {
                    if actual_str != expected_env {
                        return Err(TokenError::ScopeViolation(format!(
                            "environment mismatch: expected {expected_env}, got {actual_str}"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Helper: build claims for a scored decision.
pub fn build_claims(
    action_type: &str,
    scope: TokenScope,
    issued_by: IssuedBy,
    risk_score: u32,
    risk_tier: Tier,
    session_id: &str,
) -> TokenClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let ttl = match issued_by {
        IssuedBy::Scorer => SCORER_TTL_SECS,
        IssuedBy::Human => HUMAN_TTL_SECS,
    };
    TokenClaims {
        action_type: action_type.to_string(),
        scope,
        issued_by,
        risk_score,
        risk_tier,
        session_id: session_id.to_string(),
        safeguards: safeguards_for_tier(risk_tier),
        issued_at: now,
        expires_at: now + ttl,
    }
}

// ── Query helpers ──

fn query_string_fact(authorizer: &mut Authorizer, rule: &str) -> Option<String> {
    let facts: Vec<(String,)> = authorizer.query(rule).ok()?;
    facts.into_iter().next().map(|(s,)| s)
}

fn query_int_fact(authorizer: &mut Authorizer, rule: &str) -> Option<i64> {
    let facts: Vec<(i64,)> = authorizer.query(rule).ok()?;
    facts.into_iter().next().map(|(i,)| i)
}

fn query_date_fact(authorizer: &mut Authorizer, rule: &str) -> Option<i64> {
    // biscuit-auth stores dates as u64 unix timestamps internally
    // but queries return SystemTime
    let facts: Vec<(SystemTime,)> = authorizer.query(rule).ok()?;
    facts
        .into_iter()
        .next()
        .map(|(t,)| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64)
}

fn query_all_string_facts(authorizer: &mut Authorizer, rule: &str) -> Vec<String> {
    let facts: Vec<(String,)> = authorizer.query(rule).unwrap_or_default();
    facts.into_iter().map(|(s,)| s).collect()
}
