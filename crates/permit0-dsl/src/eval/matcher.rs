#![forbid(unsafe_code)]

use regex::Regex;

use crate::eval::path::{as_f64, as_string, resolve_path};
use crate::schema::condition::{ConditionExpr, Predicate, PredicateOps};

/// Context for evaluating conditions — wraps the data being matched against.
pub struct MatchContext<'a> {
    /// The root data to resolve field paths against.
    pub data: &'a serde_json::Value,
    /// Tool name (for the `tool` shorthand).
    pub tool_name: Option<&'a str>,
}

/// Evaluate a condition expression against a context.
pub fn eval_condition(expr: &ConditionExpr, ctx: &MatchContext<'_>) -> bool {
    match expr {
        ConditionExpr::All { all } => all.iter().all(|e| eval_condition(e, ctx)),
        ConditionExpr::Any { any } => any.iter().any(|e| eval_condition(e, ctx)),
        ConditionExpr::Not { not } => !eval_condition(not, ctx),
        ConditionExpr::Leaf(map) => {
            map.iter().all(|(field, pred)| {
                // `tool` shorthand matches tool_name
                if field == "tool" {
                    return match pred {
                        Predicate::Exact(v) => {
                            ctx.tool_name.is_some_and(|tn| {
                                v.as_str().is_some_and(|s| s == tn)
                            })
                        }
                        _ => false,
                    };
                }

                let value = resolve_field(field, ctx);
                eval_predicate(pred, value)
            })
        }
    }
}

/// Resolve a field path, handling `arg.` prefix → parameters, `tool` → tool_name.
fn resolve_field<'a>(field: &str, ctx: &MatchContext<'a>) -> Option<&'a serde_json::Value> {
    // Strip `arg.` prefix — it maps to the parameters
    let path = field.strip_prefix("arg.").unwrap_or(field);
    resolve_path(ctx.data, path)
}

fn eval_predicate(pred: &Predicate, value: Option<&serde_json::Value>) -> bool {
    match pred {
        Predicate::Exact(expected) => {
            value.is_some_and(|v| values_equal(v, expected))
        }
        Predicate::Compound(ops) => eval_compound(ops.as_ref(), value),
    }
}

fn eval_compound(ops: &PredicateOps, value: Option<&serde_json::Value>) -> bool {
    // exists check is special — it works on presence/absence
    if let Some(should_exist) = ops.exists {
        let exists = value.is_some_and(|v| !v.is_null());
        if exists != should_exist {
            return false;
        }
        // If this is the only check, return the result
        if is_only_exists(ops) {
            return true;
        }
    }

    let val = match value {
        Some(v) if !v.is_null() => v,
        _ => return false,
    };

    if let Some(ref sub) = ops.contains {
        if !as_string(val).is_some_and(|s| s.contains(sub.as_str())) {
            return false;
        }
    }

    if let Some(ref prefix) = ops.starts_with {
        if !as_string(val).is_some_and(|s| s.starts_with(prefix.as_str())) {
            return false;
        }
    }

    if let Some(ref suffix) = ops.ends_with {
        if !as_string(val).is_some_and(|s| s.ends_with(suffix.as_str())) {
            return false;
        }
    }

    if let Some(ref pattern) = ops.regex {
        if let Ok(re) = Regex::new(pattern) {
            if !as_string(val).is_some_and(|s| re.is_match(&s)) {
                return false;
            }
        } else {
            return false;
        }
    }

    if let Some(ref list) = ops.in_list {
        if !list.iter().any(|item| values_equal(val, item)) {
            return false;
        }
    }

    if let Some(ref list) = ops.not_in {
        if list.iter().any(|item| values_equal(val, item)) {
            return false;
        }
    }

    if let Some(threshold) = ops.gt {
        if !as_f64(val).is_some_and(|n| n > threshold) {
            return false;
        }
    }

    if let Some(threshold) = ops.gte {
        if !as_f64(val).is_some_and(|n| n >= threshold) {
            return false;
        }
    }

    if let Some(threshold) = ops.lt {
        if !as_f64(val).is_some_and(|n| n < threshold) {
            return false;
        }
    }

    if let Some(threshold) = ops.lte {
        if !as_f64(val).is_some_and(|n| n <= threshold) {
            return false;
        }
    }

    if let Some(true) = ops.not_empty {
        match val {
            serde_json::Value::Array(arr) => {
                if arr.is_empty() {
                    return false;
                }
            }
            serde_json::Value::String(s) => {
                if s.is_empty() {
                    return false;
                }
            }
            _ => return false,
        }
    }

    if let Some(ref url_match) = ops.matches_url {
        if let Some(url_str) = val.as_str() {
            if !eval_url_match(url_str, &url_match.host, &url_match.path, url_match.path_exact) {
                return false;
            }
        } else {
            return false;
        }
    }

    if let Some(ref contains_any) = ops.contains_any {
        let s = match as_string(val) {
            Some(s) => s,
            None => return false,
        };
        if !contains_any.iter().any(|sub| s.contains(sub.as_str())) {
            return false;
        }
    }

    true
}

fn is_only_exists(ops: &PredicateOps) -> bool {
    ops.contains.is_none()
        && ops.starts_with.is_none()
        && ops.ends_with.is_none()
        && ops.regex.is_none()
        && ops.in_list.is_none()
        && ops.not_in.is_none()
        && ops.gt.is_none()
        && ops.gte.is_none()
        && ops.lt.is_none()
        && ops.lte.is_none()
        && ops.not_empty.is_none()
        && ops.matches_url.is_none()
        && ops.any_match.is_none()
        && ops.contains_any.is_none()
        && ops.equals_ctx.is_none()
        && ops.in_set.is_none()
        && ops.not_in_set.is_none()
}

fn eval_url_match(url_str: &str, host: &str, path: &str, path_exact: bool) -> bool {
    // Simple URL parsing without pulling in the `url` crate
    let without_scheme = url_str
        .strip_prefix("https://")
        .or_else(|| url_str.strip_prefix("http://"))
        .unwrap_or(url_str);

    let (parsed_host, parsed_path) = match without_scheme.find('/') {
        Some(idx) => {
            let h = &without_scheme[..idx];
            let p = &without_scheme[idx..];
            // Strip query string
            let p = p.split('?').next().unwrap_or(p);
            (h, p)
        }
        None => (without_scheme, "/"),
    };

    // Strip port from host
    let parsed_host = parsed_host.split(':').next().unwrap_or(parsed_host);

    if parsed_host != host {
        return false;
    }

    if path_exact {
        parsed_path == path
    } else {
        parsed_path.starts_with(path)
    }
}

fn values_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    // Allow cross-type comparison for string/number
    match (a, b) {
        (serde_json::Value::String(sa), serde_json::Value::String(sb)) => sa == sb,
        (serde_json::Value::Number(na), serde_json::Value::Number(nb)) => na == nb,
        (serde_json::Value::Bool(ba), serde_json::Value::Bool(bb)) => ba == bb,
        (serde_json::Value::Null, serde_json::Value::Null) => true,
        // String ↔ number coercion
        (serde_json::Value::String(s), serde_json::Value::Number(n)) => {
            n.as_f64()
                .is_some_and(|nf| s.parse::<f64>().is_ok_and(|sf| (sf - nf).abs() < f64::EPSILON))
        }
        (serde_json::Value::Number(_), serde_json::Value::String(_)) => values_equal(b, a),
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_from<'a>(data: &'a serde_json::Value, tool: Option<&'a str>) -> MatchContext<'a> {
        MatchContext {
            data,
            tool_name: tool,
        }
    }

    fn parse_condition(yaml: &str) -> ConditionExpr {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn tool_shorthand() {
        let cond = parse_condition("tool: http");
        let data = json!({});
        assert!(eval_condition(&cond, &ctx_from(&data, Some("http"))));
        assert!(!eval_condition(&cond, &ctx_from(&data, Some("bash"))));
    }

    #[test]
    fn exact_match() {
        let cond = parse_condition("method: POST");
        let data = json!({"method": "POST"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
    }

    #[test]
    fn all_combinator() {
        let cond = parse_condition(
            r#"
all:
  - tool: http
  - method: POST
"#,
        );
        let data = json!({"method": "POST"});
        assert!(eval_condition(&cond, &ctx_from(&data, Some("http"))));
        assert!(!eval_condition(&cond, &ctx_from(&data, Some("bash"))));
    }

    #[test]
    fn any_combinator() {
        let cond = parse_condition(
            r#"
any:
  - method: POST
  - method: PUT
"#,
        );
        let data = json!({"method": "PUT"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        let data2 = json!({"method": "GET"});
        assert!(!eval_condition(&cond, &ctx_from(&data2, None)));
    }

    #[test]
    fn not_combinator() {
        let cond = parse_condition(
            r#"
not:
  method: DELETE
"#,
        );
        let data = json!({"method": "POST"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
    }

    #[test]
    fn contains_predicate() {
        let cond = parse_condition(
            r#"
url:
  contains: stripe.com
"#,
        );
        let data = json!({"url": "https://api.stripe.com/v1/charges"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
    }

    #[test]
    fn numeric_comparison() {
        let cond = parse_condition(
            r#"
amount:
  gt: 1000
"#,
        );
        let data = json!({"amount": 5000});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        let data2 = json!({"amount": 500});
        assert!(!eval_condition(&cond, &ctx_from(&data2, None)));
    }

    #[test]
    fn url_match() {
        let cond = parse_condition(
            r#"
url:
  matches_url:
    host: api.stripe.com
    path: /v1/charges
"#,
        );
        let data = json!({"url": "https://api.stripe.com/v1/charges"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        // Prefix match
        let data2 = json!({"url": "https://api.stripe.com/v1/charges/ch_123"});
        assert!(eval_condition(&cond, &ctx_from(&data2, None)));
        // Wrong host
        let data3 = json!({"url": "https://api.evil.com/v1/charges"});
        assert!(!eval_condition(&cond, &ctx_from(&data3, None)));
    }

    #[test]
    fn url_match_exact_path() {
        let cond = parse_condition(
            r#"
url:
  matches_url:
    host: api.stripe.com
    path: /v1/charges
    path_exact: true
"#,
        );
        let data = json!({"url": "https://api.stripe.com/v1/charges"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        let data2 = json!({"url": "https://api.stripe.com/v1/charges/ch_123"});
        assert!(!eval_condition(&cond, &ctx_from(&data2, None)));
    }

    #[test]
    fn exists_predicate() {
        let cond = parse_condition(
            r#"
customer:
  exists: true
"#,
        );
        let data = json!({"customer": "cus_123"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        let data2 = json!({});
        assert!(!eval_condition(&cond, &ctx_from(&data2, None)));
    }

    #[test]
    fn in_list_predicate() {
        let cond = parse_condition(
            r#"
method:
  in: [POST, PUT, PATCH]
"#,
        );
        let data = json!({"method": "PUT"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        let data2 = json!({"method": "GET"});
        assert!(!eval_condition(&cond, &ctx_from(&data2, None)));
    }

    #[test]
    fn nested_path() {
        let cond = parse_condition("body.amount: 5000");
        let data = json!({"body": {"amount": 5000}});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
    }

    #[test]
    fn regex_predicate() {
        let cond = parse_condition(
            r#"
command:
  regex: "rm\\s+-rf"
"#,
        );
        let data = json!({"command": "rm -rf /tmp"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
    }

    #[test]
    fn contains_any_predicate() {
        let cond = parse_condition(
            r#"
body:
  contains_any: [password, secret]
"#,
        );
        let data = json!({"body": "my secret value"});
        assert!(eval_condition(&cond, &ctx_from(&data, None)));
        let data2 = json!({"body": "nothing here"});
        assert!(!eval_condition(&cond, &ctx_from(&data2, None)));
    }
}
