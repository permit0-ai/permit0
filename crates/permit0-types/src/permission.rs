#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Three final outcomes visible to callers of `get_permission()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    Allow,
    HumanInTheLoop,
    Deny,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::HumanInTheLoop => write!(f, "HUMAN"),
            Self::Deny => write!(f, "DENY"),
        }
    }
}
