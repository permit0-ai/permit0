#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

use permit0_types::{Entities, Tier};

/// A record of a single action within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action_type: String,
    pub tier: Tier,
    pub flags: Vec<String>,
    /// Unix timestamp (seconds, f64 for sub-second precision).
    pub timestamp: f64,
    pub entities: Entities,
}

/// Filter for scoping session queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionFilter {
    /// Single action type filter.
    pub action_type: Option<String>,
    /// Multiple action types (OR).
    pub action_types: Option<Vec<String>>,
    /// Entity field conditions: (field_name, expected_value).
    pub entity_match: Option<Vec<(String, Value)>>,
    /// Time window in minutes (only records within last N minutes).
    pub within_minutes: Option<u64>,
}

impl SessionFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_action_type(mut self, at: impl Into<String>) -> Self {
        self.action_type = Some(at.into());
        self
    }

    pub fn with_action_types(mut self, ats: Vec<String>) -> Self {
        self.action_types = Some(ats);
        self
    }

    pub fn with_entity_match(mut self, field: impl Into<String>, value: Value) -> Self {
        self.entity_match
            .get_or_insert_with(Vec::new)
            .push((field.into(), value));
        self
    }

    pub fn with_within_minutes(mut self, mins: u64) -> Self {
        self.within_minutes = Some(mins);
        self
    }
}
