#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use regex::Regex;

use crate::eval::path::{as_f64, as_string, resolve_path};
use crate::schema::condition::{ConditionExpr, Predicate, PredicateOps};

/// Named sets keyed by dotted identifier (e.g., `org.trusted_domains`).
/// Values inside a set are string-compared (membership by exact equality).
pub type NamedSets = HashMap<String, HashSet<String>>;

/// Context for evaluating conditions — wraps the data being matched against.
pub struct MatchContext<'a> {
    /// The root data to resolve field paths against.
    pub data: &'a serde_json::Value,
    /// Tool name (for the `tool` shorthand).
    pub tool_name: Option<&'a str>,
    /// Named sets used by `in_set` / `not_in_set` predicates. `None` means
    /// no sets are configured — predicates that reference sets will fail closed
    /// (treated as "not in the set" for `in_set`, and "is in the set" for
    /// `not_in_set`) so missing configuration never opens a hole.
    pub named_sets: Option<&'a NamedSets>,
}

impl<'a> MatchContext<'a> {
    /// Construct a context with no named sets (for use cases that don't need them —
    /// notably normalizer matching, which operates purely on tool parameters).
    pub fn new(data: &'a serde_json::Value, tool_name: Option<&'a str>) -> Self {
        Self {
            data,
            tool_name,
            named_sets: None,
        }
    }

    /// Construct a context with named sets.
    pub fn with_sets(
        data: &'a serde_json::Value,
        tool_name: Option<&'a str>,
        named_sets: Option<&'a NamedSets>,
    ) -> Self {
        Self {
            data,
            tool_name,
            named_sets,
        }
    }
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
                eval_predicate(pred, value, ctx)
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

fn eval_predicate(pred: &Predicate, value: Option<&serde_json::Value>, ctx: &MatchContext<'_>) -> bool {
    match pred {
        Predicate::Exact(expected) => {
            value.is_some_and(|v| values_equal(v, expected))
        }
        Predicate::Compound(ops) => eval_compound(ops.as_ref(), value, ctx),
    }
}

fn eval_compound(ops: &PredicateOps, value: Option<&serde_json::Value>, ctx: &MatchContext<'_>) -> bool {
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
        // Array case: check if any element of the array equals any needle (exact match).
        // Useful for matching session.distinct_flags, session.flag_sequence, etc.
        if let serde_json::Value::Array(arr) = val {
            let matched = contains_any.iter().any(|needle| {
                arr.iter().any(|item| {
                    item.as_str().is_some_and(|s| s == needle.as_str())
                })
            });
            if !matched {
                return false;
            }
        } else {
            // String case: substring match (original behavior).
            let s = match as_string(val) {
                Some(s) => s,
                None => return false,
            };
            if !contains_any.iter().any(|sub| s.contains(sub.as_str())) {
                return false;
            }
        }
    }

    if let Some(ref set_name) = ops.in_set {
        if !is_in_named_set(val, set_name, ctx) {
            return false;
        }
    }

    if let Some(ref set_name) = ops.not_in_set {
        if is_in_named_set(val, set_name, ctx) {
            return false;
        }
    }

    true
}

/// Membership check against a named set.
///
/// Resolves the value to its string form, then checks against the set
/// identified by `set_name`. Comparison is case-insensitive and supports
/// suffix match for dotted identifiers (so a set entry `github.com`
/// matches values `github.com` and `*.github.com`).
///
/// If the set is not configured, returns `false` (fail closed — callers
/// decide whether that's "block" or "allow" via `in_set` vs `not_in_set`).
fn is_in_named_set(val: &serde_json::Value, set_name: &str, ctx: &MatchContext<'_>) -> bool {
    let sets = match ctx.named_sets {
        Some(s) => s,
        None => return false,
    };
    let set = match sets.get(set_name) {
        Some(s) => s,
        None => return false,
    };

    // Resolve to a string for comparison. For arrays, check if any element
    // is a member (useful for multi-value fields like email recipient lists).
    match val {
        serde_json::Value::Array(arr) => arr.iter().any(|item| {
            item.as_str()
                .is_some_and(|s| set_contains(set, s))
        }),
        _ => match as_string(val) {
            Some(s) => set_contains(set, &s),
            None => false,
        },
    }
}

/// Check a string against a set with case-insensitive equality + dotted-suffix
/// match (so `api.github.com` is in a set containing `github.com`).
fn set_contains(set: &HashSet<String>, needle: &str) -> bool {
    let needle_lower = needle.to_lowercase();
    set.iter().any(|entry| {
        let entry = entry.to_lowercase();
        needle_lower == entry || needle_lower.ends_with(&format!(".{entry}"))
    })
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
            named_sets: None,
        }
    }

    fn ctx_with_sets<'a>(
        data: &'a serde_json::Value,
        tool: Option<&'a str>,
        sets: &'a NamedSets,
    ) -> MatchContext<'a> {
        MatchContext {
            data,
            tool_name: tool,
            named_sets: Some(sets),
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

    #[test]
    fn in_set_exact_match() {
        let mut sets: NamedSets = HashMap::new();
        sets.insert(
            "org.trusted_domains".to_string(),
            ["github.com".to_string(), "stripe.com".to_string()]
                .into_iter()
                .collect(),
        );

        let cond = parse_condition(
            r#"
host:
  in_set: "org.trusted_domains"
"#,
        );

        let yes = json!({"host": "github.com"});
        assert!(eval_condition(&cond, &ctx_with_sets(&yes, None, &sets)));

        let no = json!({"host": "evil.com"});
        assert!(!eval_condition(&cond, &ctx_with_sets(&no, None, &sets)));
    }

    #[test]
    fn in_set_suffix_match() {
        // `github.com` in the set should match `api.github.com` (subdomain).
        let mut sets: NamedSets = HashMap::new();
        sets.insert(
            "org.trusted_domains".to_string(),
            ["github.com".to_string()].into_iter().collect(),
        );

        let cond = parse_condition(
            r#"
host:
  in_set: "org.trusted_domains"
"#,
        );

        let subdomain = json!({"host": "api.github.com"});
        assert!(eval_condition(&cond, &ctx_with_sets(&subdomain, None, &sets)));

        // Guard against string-suffix tricking: `eviltgithub.com` must not match `github.com`.
        let trick = json!({"host": "eviltgithub.com"});
        assert!(!eval_condition(&cond, &ctx_with_sets(&trick, None, &sets)));
    }

    #[test]
    fn in_set_case_insensitive() {
        let mut sets: NamedSets = HashMap::new();
        sets.insert(
            "org.trusted_domains".to_string(),
            ["GitHub.com".to_string()].into_iter().collect(),
        );

        let cond = parse_condition(
            r#"
host:
  in_set: "org.trusted_domains"
"#,
        );

        let mixed = json!({"host": "API.GITHUB.com"});
        assert!(eval_condition(&cond, &ctx_with_sets(&mixed, None, &sets)));
    }

    #[test]
    fn not_in_set() {
        let mut sets: NamedSets = HashMap::new();
        sets.insert(
            "org.trusted_domains".to_string(),
            ["github.com".to_string()].into_iter().collect(),
        );

        let cond = parse_condition(
            r#"
host:
  not_in_set: "org.trusted_domains"
"#,
        );

        let untrusted = json!({"host": "attacker.example.com"});
        assert!(eval_condition(&cond, &ctx_with_sets(&untrusted, None, &sets)));

        let trusted = json!({"host": "github.com"});
        assert!(!eval_condition(&cond, &ctx_with_sets(&trusted, None, &sets)));
    }

    #[test]
    fn in_set_missing_sets_fails_closed() {
        // When no named_sets are provided, `in_set` returns false (nothing is
        // in the set) and `not_in_set` returns true (everything is "not in").
        // This is the fail-closed behaviour: missing config doesn't open holes.
        let cond = parse_condition(
            r#"
host:
  in_set: "org.trusted_domains"
"#,
        );
        let data = json!({"host": "github.com"});
        assert!(!eval_condition(&cond, &ctx_from(&data, None)));
    }

    #[test]
    fn in_set_unknown_set_name_fails_closed() {
        let sets: NamedSets = HashMap::new();
        let cond = parse_condition(
            r#"
host:
  in_set: "org.typo_sett"
"#,
        );
        let data = json!({"host": "github.com"});
        assert!(!eval_condition(&cond, &ctx_with_sets(&data, None, &sets)));
    }

    #[test]
    fn in_set_array_field_any_match() {
        // When the field is an array (e.g., email recipients), in_set passes
        // if ANY element is in the named set.
        let mut sets: NamedSets = HashMap::new();
        sets.insert(
            "org.domains".to_string(),
            ["acme.com".to_string()].into_iter().collect(),
        );
        let cond = parse_condition(
            r#"
recipient_domains:
  in_set: "org.domains"
"#,
        );
        // Note: our set-contains does case-insensitive equality + dotted-suffix
        // match. "alice@acme.com" wouldn't match because it's not a dotted form
        // ending in `.acme.com`. Raw domains in the array is the canonical shape.
        let yes = json!({"recipient_domains": ["evil.com", "acme.com"]});
        assert!(eval_condition(&cond, &ctx_with_sets(&yes, None, &sets)));

        let no = json!({"recipient_domains": ["evil.com", "other.com"]});
        assert!(!eval_condition(&cond, &ctx_with_sets(&no, None, &sets)));
    }

    #[test]
    fn contains_any_on_array_field() {
        // For array fields (e.g., session.distinct_flags), contains_any matches
        // exact element equality, not substring.
        let cond = parse_condition(
            r#"
distinct_flags:
  contains_any: [DESTRUCTION, PHYSICAL]
"#,
        );
        let matches_destruction = json!({"distinct_flags": ["EXPOSURE", "DESTRUCTION", "MUTATION"]});
        assert!(eval_condition(&cond, &ctx_from(&matches_destruction, None)));

        let no_match = json!({"distinct_flags": ["EXPOSURE", "MUTATION"]});
        assert!(!eval_condition(&cond, &ctx_from(&no_match, None)));

        // Substring match must NOT trigger on arrays (semantic difference vs strings)
        let substring_only = json!({"distinct_flags": ["DESTRUCTION_LITE"]});
        assert!(!eval_condition(&cond, &ctx_from(&substring_only, None)));
    }
}
