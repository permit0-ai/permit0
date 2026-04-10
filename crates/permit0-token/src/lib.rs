#![forbid(unsafe_code)]
#![doc = "Biscuit-based capability tokens for permit0."]

pub mod error;
pub mod provider;
pub mod types;

pub use error::TokenError;
pub use provider::{BiscuitTokenProvider, build_claims};
pub use types::{
    IssuedBy, Safeguard, TokenClaims, TokenScope, VerificationResult, HUMAN_TTL_SECS,
    SCORER_TTL_SECS, safeguards_for_tier,
};
