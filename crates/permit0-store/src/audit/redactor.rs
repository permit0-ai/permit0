#![forbid(unsafe_code)]

use regex::Regex;
use std::sync::LazyLock;

/// Trait for redacting sensitive data from tool call values before audit signing.
pub trait Redactor: Send + Sync {
    /// Redact sensitive values from a JSON value, returning a new value.
    fn redact(&self, value: &serde_json::Value) -> serde_json::Value;
}

/// Built-in redactor that matches common secret patterns.
pub struct BuiltinRedactor {
    /// Additional field-name patterns (regex) to redact.
    extra_field_patterns: Vec<Regex>,
}

/// Patterns for field names that should be redacted.
static FIELD_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)password",
        r"(?i)secret",
        r"(?i)token",
        r"(?i)api[_-]?key",
        r"(?i)authorization",
        r"(?i)credential",
        r"(?i)ssn",
        r"(?i)dob",
        r"(?i)mrn",
        r"(?i)private[_-]?key",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("invalid built-in pattern"))
    .collect()
});

/// Patterns for string values that look like secrets.
static VALUE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)^Bearer\s+\S+",
        r"^sk_live_\S+",
        r"^sk_test_\S+",
        r"^ghp_\S+",
        r"^gho_\S+",
        r"^github_pat_\S+",
        r"^xox[bpsa]-\S+",
        r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("invalid built-in value pattern"))
    .collect()
});

const REDACTED: &str = "[REDACTED]";

impl BuiltinRedactor {
    pub fn new() -> Self {
        Self {
            extra_field_patterns: Vec::new(),
        }
    }

    /// Add domain-specific field name patterns (e.g. `body.patient_id` for HIPAA).
    pub fn with_extra_patterns(mut self, patterns: Vec<String>) -> Self {
        self.extra_field_patterns = patterns.iter().filter_map(|p| Regex::new(p).ok()).collect();
        self
    }

    fn should_redact_field(&self, field_name: &str) -> bool {
        FIELD_PATTERNS.iter().any(|p| p.is_match(field_name))
            || self
                .extra_field_patterns
                .iter()
                .any(|p| p.is_match(field_name))
    }

    fn should_redact_value(value: &str) -> bool {
        VALUE_PATTERNS.iter().any(|p| p.is_match(value))
    }

    fn redact_value(&self, key: &str, value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::String(s) => {
                if self.should_redact_field(key) || Self::should_redact_value(s) {
                    serde_json::Value::String(REDACTED.into())
                } else {
                    value.clone()
                }
            }
            serde_json::Value::Object(map) => {
                let redacted_map: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.redact_value(k, v)))
                    .collect();
                serde_json::Value::Object(redacted_map)
            }
            serde_json::Value::Array(arr) => {
                let redacted_arr: Vec<serde_json::Value> =
                    arr.iter().map(|v| self.redact_value(key, v)).collect();
                serde_json::Value::Array(redacted_arr)
            }
            // Numbers, bools, null: redact if field name matches
            _ => {
                if self.should_redact_field(key) {
                    serde_json::Value::String(REDACTED.into())
                } else {
                    value.clone()
                }
            }
        }
    }
}

impl Default for BuiltinRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor for BuiltinRedactor {
    fn redact(&self, value: &serde_json::Value) -> serde_json::Value {
        self.redact_value("", value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_password_field() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"password": "hunter2", "username": "alice"});
        let output = redactor.redact(&input);
        assert_eq!(output["password"], REDACTED);
        assert_eq!(output["username"], "alice");
    }

    #[test]
    fn redacts_api_key_field() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"api_key": "sk_live_abc123", "name": "test"});
        let output = redactor.redact(&input);
        assert_eq!(output["api_key"], REDACTED);
        assert_eq!(output["name"], "test");
    }

    #[test]
    fn redacts_bearer_token_value() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"header": "Bearer eyJhbGciOiJIUzI1NiJ9.test"});
        let output = redactor.redact(&input);
        assert_eq!(output["header"], REDACTED);
    }

    #[test]
    fn redacts_github_pat_value() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"value": "ghp_abc123def456"});
        let output = redactor.redact(&input);
        assert_eq!(output["value"], REDACTED);
    }

    #[test]
    fn redacts_sk_live_value() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"key": "sk_live_abc123"});
        let output = redactor.redact(&input);
        assert_eq!(output["key"], REDACTED);
    }

    #[test]
    fn redacts_nested_objects() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"auth": {"token": "secret123", "user": "bob"}});
        let output = redactor.redact(&input);
        assert_eq!(output["auth"]["token"], REDACTED);
        assert_eq!(output["auth"]["user"], "bob");
    }

    #[test]
    fn redacts_arrays() {
        let redactor = BuiltinRedactor::new();
        // "tokens" field name matches the "token" pattern, so all values redacted
        let input = json!({"tokens": ["ghp_abc", "normal_value"]});
        let output = redactor.redact(&input);
        let arr = output["tokens"].as_array().unwrap();
        assert_eq!(arr[0], REDACTED);
        assert_eq!(arr[1], REDACTED);

        // Array under non-sensitive key: only value-pattern matches redacted
        let input2 = json!({"items": ["ghp_abc", "normal_value"]});
        let output2 = redactor.redact(&input2);
        let arr2 = output2["items"].as_array().unwrap();
        assert_eq!(arr2[0], REDACTED); // value pattern match
        assert_eq!(arr2[1], "normal_value");
    }

    #[test]
    fn redacts_ssn_field() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"ssn": "123-45-6789"});
        let output = redactor.redact(&input);
        assert_eq!(output["ssn"], REDACTED);
    }

    #[test]
    fn preserves_non_sensitive_data() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"action": "send_email", "to": "bob@example.com", "count": 5});
        let output = redactor.redact(&input);
        assert_eq!(output, input);
    }

    #[test]
    fn extra_patterns_work() {
        let redactor = BuiltinRedactor::new().with_extra_patterns(vec!["patient_id".into()]);
        let input = json!({"patient_id": "P12345", "diagnosis": "healthy"});
        let output = redactor.redact(&input);
        assert_eq!(output["patient_id"], REDACTED);
        assert_eq!(output["diagnosis"], "healthy");
    }

    #[test]
    fn case_insensitive_field_matching() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"PASSWORD": "secret", "Api_Key": "key123"});
        let output = redactor.redact(&input);
        assert_eq!(output["PASSWORD"], REDACTED);
        assert_eq!(output["Api_Key"], REDACTED);
    }

    #[test]
    fn jwt_value_redacted() {
        let redactor = BuiltinRedactor::new();
        let input = json!({"data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0"});
        let output = redactor.redact(&input);
        assert_eq!(output["data"], REDACTED);
    }
}
