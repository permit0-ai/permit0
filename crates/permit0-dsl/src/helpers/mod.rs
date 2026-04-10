#![forbid(unsafe_code)]

use std::collections::HashMap;

/// A helper function: takes JSON arguments, returns a JSON value.
pub type HelperFn = fn(&[serde_json::Value]) -> serde_json::Value;

/// Registry of all closed helpers — fixed at compile time.
pub fn build_helper_registry() -> HashMap<&'static str, (HelperFn, usize)> {
    let mut m: HashMap<&'static str, (HelperFn, usize)> = HashMap::new();
    m.insert("classify_destination", (classify_destination, 2));
    m.insert("recipient_scope", (recipient_scope, 2));
    m.insert("count_pipes", (count_pipes, 1));
    m.insert("extract_domain", (extract_domain, 1));
    m.insert("is_private_ip", (is_private_ip, 1));
    m.insert("parse_path_depth", (parse_path_depth, 1));
    m.insert("classify_file_type", (classify_file_type, 1));
    m.insert("extract_amount_cents", (extract_amount_cents, 2));
    m.insert("detect_pii_patterns", (detect_pii_patterns, 1));
    m.insert("url_host", (url_host, 1));
    m.insert("url_path", (url_path, 1));
    m.insert("string_length", (string_length, 1));
    m.insert("list_length", (list_length, 1));
    m
}

fn str_arg(args: &[serde_json::Value], idx: usize) -> String {
    args.get(idx)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Compares an account ID to the org's own account.
fn classify_destination(args: &[serde_json::Value]) -> serde_json::Value {
    let account = str_arg(args, 0);
    let org_account = str_arg(args, 1);
    let result = if account.is_empty() {
        "unknown"
    } else if account == org_account {
        "internal"
    } else {
        "external"
    };
    serde_json::Value::String(result.into())
}

/// Classifies email recipients by domain.
fn recipient_scope(args: &[serde_json::Value]) -> serde_json::Value {
    let email_or_list = &args[0];
    let org_domain = str_arg(args, 1);

    let emails: Vec<&str> = match email_or_list {
        serde_json::Value::String(s) => s.split(',').map(str::trim).collect(),
        serde_json::Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => return serde_json::Value::String("unknown".into()),
    };

    if emails.is_empty() {
        return serde_json::Value::String("unknown".into());
    }

    let mut has_internal = false;
    let mut has_external = false;
    let mut has_self = false;

    for email in &emails {
        if let Some(domain) = email.split('@').nth(1) {
            if domain == org_domain {
                has_internal = true;
            } else {
                has_external = true;
            }
            // "self" if sending to the same org domain — simplified
            if emails.len() == 1 && domain == org_domain {
                has_self = true;
            }
        }
    }

    let scope = if has_self && !has_external {
        "self"
    } else if has_internal && has_external {
        "mixed"
    } else if has_external {
        "external"
    } else {
        "internal"
    };

    serde_json::Value::String(scope.into())
}

/// Counts pipe characters in a shell command.
fn count_pipes(args: &[serde_json::Value]) -> serde_json::Value {
    let cmd = str_arg(args, 0);
    let count = cmd.chars().filter(|c| *c == '|').count();
    serde_json::json!(count)
}

/// Extracts domain from an email address.
fn extract_domain(args: &[serde_json::Value]) -> serde_json::Value {
    let email = str_arg(args, 0);
    let domain = email.split('@').nth(1).unwrap_or("");
    serde_json::Value::String(domain.into())
}

/// Checks if an IP/URL targets private network ranges.
fn is_private_ip(args: &[serde_json::Value]) -> serde_json::Value {
    let input = str_arg(args, 0);
    // Extract host part if it's a URL
    let host = input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))
        .unwrap_or(&input);
    let host = host.split('/').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);

    let is_private = host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.2")
        || host.starts_with("172.30.")
        || host.starts_with("172.31.")
        || host == "localhost"
        || host == "127.0.0.1"
        || host == "::1";

    serde_json::Value::Bool(is_private)
}

/// Counts path segments.
fn parse_path_depth(args: &[serde_json::Value]) -> serde_json::Value {
    let path = str_arg(args, 0);
    let depth = path.split('/').filter(|s| !s.is_empty()).count();
    serde_json::json!(depth)
}

/// Classifies file by extension.
fn classify_file_type(args: &[serde_json::Value]) -> serde_json::Value {
    let filename = str_arg(args, 0);
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    let classification = match ext.as_str() {
        "rs" | "py" | "js" | "ts" | "go" | "java" | "c" | "cpp" | "rb" | "swift" | "kt"
        | "sh" | "bash" | "zsh" | "ps1" => "code",
        "json" | "csv" | "xml" | "parquet" | "avro" | "sql" | "db" | "sqlite" => "data",
        "yaml" | "yml" | "toml" | "ini" | "conf" | "cfg" | "env" | "properties" => "config",
        "exe" | "dll" | "so" | "dylib" | "bin" | "wasm" | "zip" | "tar" | "gz" => "binary",
        _ => "unknown",
    };
    serde_json::Value::String(classification.into())
}

/// Normalizes amount to cents.
fn extract_amount_cents(args: &[serde_json::Value]) -> serde_json::Value {
    let amount = &args[0];
    let _currency = str_arg(args, 1);
    // If already an integer, assume it's already in cents
    let cents = match amount {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(f) = n.as_f64() {
                (f * 100.0).round() as i64
            } else {
                0
            }
        }
        serde_json::Value::String(s) => {
            if let Ok(f) = s.parse::<f64>() {
                (f * 100.0).round() as i64
            } else {
                0
            }
        }
        _ => 0,
    };
    serde_json::json!(cents)
}

/// Checks for common PII patterns.
fn detect_pii_patterns(args: &[serde_json::Value]) -> serde_json::Value {
    let text = str_arg(args, 0);
    // Simple patterns — SSN, email, phone
    let has_ssn = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
        .is_ok_and(|re| re.is_match(&text));
    let has_email = text.contains('@') && text.contains('.');
    let has_phone = regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")
        .is_ok_and(|re| re.is_match(&text));
    serde_json::Value::Bool(has_ssn || has_email || has_phone)
}

/// Extracts the host from a URL.
fn url_host(args: &[serde_json::Value]) -> serde_json::Value {
    let url = str_arg(args, 0);
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url);
    let host = without_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(host);
    serde_json::Value::String(host.into())
}

/// Extracts the path from a URL.
fn url_path(args: &[serde_json::Value]) -> serde_json::Value {
    let url = str_arg(args, 0);
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url);
    let path = match without_scheme.find('/') {
        Some(idx) => {
            let p = &without_scheme[idx..];
            p.split('?').next().unwrap_or(p)
        }
        None => "/",
    };
    serde_json::Value::String(path.into())
}

/// Returns the length of a string.
fn string_length(args: &[serde_json::Value]) -> serde_json::Value {
    match &args[0] {
        serde_json::Value::String(s) => serde_json::json!(s.len()),
        _ => serde_json::json!(0),
    }
}

/// Returns the length of a list.
fn list_length(args: &[serde_json::Value]) -> serde_json::Value {
    match &args[0] {
        serde_json::Value::Array(arr) => serde_json::json!(arr.len()),
        _ => serde_json::json!(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_classify_destination() {
        assert_eq!(
            classify_destination(&[json!("acct_123"), json!("acct_123")]),
            json!("internal")
        );
        assert_eq!(
            classify_destination(&[json!("acct_other"), json!("acct_123")]),
            json!("external")
        );
        assert_eq!(
            classify_destination(&[json!(""), json!("acct_123")]),
            json!("unknown")
        );
    }

    #[test]
    fn test_count_pipes() {
        assert_eq!(count_pipes(&[json!("ls | grep foo | wc -l")]), json!(2));
        assert_eq!(count_pipes(&[json!("echo hello")]), json!(0));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain(&[json!("user@example.com")]),
            json!("example.com")
        );
    }

    #[test]
    fn test_is_private_ip() {
        assert_eq!(is_private_ip(&[json!("192.168.1.1")]), json!(true));
        assert_eq!(is_private_ip(&[json!("8.8.8.8")]), json!(false));
        assert_eq!(is_private_ip(&[json!("http://localhost:3000")]), json!(true));
    }

    #[test]
    fn test_classify_file_type() {
        assert_eq!(classify_file_type(&[json!("main.rs")]), json!("code"));
        assert_eq!(classify_file_type(&[json!("data.csv")]), json!("data"));
        assert_eq!(classify_file_type(&[json!("config.yaml")]), json!("config"));
        assert_eq!(classify_file_type(&[json!("app.exe")]), json!("binary"));
    }

    #[test]
    fn test_url_host_and_path() {
        assert_eq!(
            url_host(&[json!("https://api.stripe.com/v1/charges")]),
            json!("api.stripe.com")
        );
        assert_eq!(
            url_path(&[json!("https://api.stripe.com/v1/charges?key=val")]),
            json!("/v1/charges")
        );
    }

    #[test]
    fn test_string_length() {
        assert_eq!(string_length(&[json!("hello")]), json!(5));
    }

    #[test]
    fn test_list_length() {
        assert_eq!(list_length(&[json!([1, 2, 3])]), json!(3));
    }

    #[test]
    fn test_recipient_scope() {
        assert_eq!(
            recipient_scope(&[json!("user@acme.com"), json!("acme.com")]),
            json!("self")
        );
        assert_eq!(
            recipient_scope(&[json!("user@external.com"), json!("acme.com")]),
            json!("external")
        );
    }

    #[test]
    fn test_parse_path_depth() {
        assert_eq!(parse_path_depth(&[json!("/a/b/c")]), json!(3));
        assert_eq!(parse_path_depth(&[json!("/")]), json!(0));
    }

    #[test]
    fn test_detect_pii() {
        assert_eq!(
            detect_pii_patterns(&[json!("SSN: 123-45-6789")]),
            json!(true)
        );
        assert_eq!(
            detect_pii_patterns(&[json!("hello world")]),
            json!(false)
        );
    }

    #[test]
    fn all_helpers_registered() {
        let reg = build_helper_registry();
        assert_eq!(reg.len(), 13);
    }
}
