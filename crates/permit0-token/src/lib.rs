#![forbid(unsafe_code)]
#![doc = "Biscuit-based capability tokens for permit0."]

pub mod error;
pub mod provider;
pub mod types;

pub use error::TokenError;
pub use provider::{BiscuitTokenProvider, build_claims};
pub use types::{
    HUMAN_TTL_SECS, IssuedBy, SCORER_TTL_SECS, Safeguard, TokenClaims, TokenScope,
    VerificationResult, safeguards_for_tier,
};
