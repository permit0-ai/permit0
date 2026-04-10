#![forbid(unsafe_code)]

/// Resolve a dotted path against a JSON value.
/// Returns `None` if any intermediate segment is missing.
pub fn resolve_path<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = segment.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Extract a string value from a JSON value, coercing numbers and bools.
pub fn as_string(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Extract an f64 from a JSON value.
pub fn as_f64(val: &serde_json::Value) -> Option<f64> {
    match val {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_nested() {
        let data = json!({"a": {"b": {"c": 42}}});
        assert_eq!(resolve_path(&data, "a.b.c"), Some(&json!(42)));
    }

    #[test]
    fn resolve_missing() {
        let data = json!({"a": 1});
        assert_eq!(resolve_path(&data, "a.b"), None);
    }

    #[test]
    fn resolve_array_index() {
        let data = json!({"items": [10, 20, 30]});
        assert_eq!(resolve_path(&data, "items.1"), Some(&json!(20)));
    }
}
