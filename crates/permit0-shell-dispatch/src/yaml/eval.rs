//! Evaluate a dispatcher-YAML parameter tree against a [`ParsedCommand`].
//!
//! Three layers, from inside out:
//!
//! 1. [`resolve_source_path`] — take a `"flags.to"` / `"positional.0"` /
//!    `"subcommands.1"` / `"program"` / ... string, look up the value in
//!    the parsed command.
//! 2. [`eval_field_spec`] — take a [`FieldSpec`], resolve its `from` (or
//!    `value`), apply `join` / `first` / `default` / `type`, return a JSON
//!    value.
//! 3. [`eval_parameters`] — walk a `serde_yaml::Value` tree, detect which
//!    nodes are FieldSpecs vs nested literal objects, recurse.

use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::parsed::{FlagValue, ParsedCommand};

use super::schema::{FIELD_SPEC_KEYS, FieldSpec, FieldType};

/// Resolve a dotted source path against a parsed command.
///
/// Supported paths:
///
/// | Path | Yields |
/// |------|--------|
/// | `flags` | the full flag map as a JSON object (spread/passthrough pattern) |
/// | `flags.<name>` | the flag's value (string / list / bool depending on how it was seen) |
/// | `flags_list.<name>` | always a list; singletons wrap to `[value]`; bools yield `None` |
/// | `flag_exists.<name>` | bool |
/// | `positional` | the full positional array |
/// | `positional.<N>` | the Nth positional, if present |
/// | `subcommands` | the full sub-command array |
/// | `subcommands.<N>` | the Nth sub-command, if present |
/// | `program` | the CLI program name |
/// | `original` | the original command string |
///
/// Returns `None` when the path resolves to a missing value — callers
/// decide whether to substitute a default or drop the field.
pub fn resolve_source_path(path: &str, parsed: &ParsedCommand) -> Option<JsonValue> {
    let trimmed = path.trim();
    let parts: Vec<&str> = trimmed.splitn(2, '.').collect();
    match parts.as_slice() {
        ["program"] => Some(JsonValue::String(parsed.program.clone())),
        ["original"] => Some(JsonValue::String(parsed.original.clone())),

        // Whole-collection accessors — useful for passthrough / spread.
        ["flags"] => {
            let mut m = serde_json::Map::new();
            for (k, v) in &parsed.flags {
                m.insert(k.clone(), v.to_json());
            }
            Some(JsonValue::Object(m))
        }
        ["positional"] => Some(JsonValue::Array(
            parsed
                .positional
                .iter()
                .map(|s| JsonValue::String(s.clone()))
                .collect(),
        )),
        ["subcommands"] => Some(JsonValue::Array(
            parsed
                .subcommands
                .iter()
                .map(|s| JsonValue::String(s.clone()))
                .collect(),
        )),

        // Keyed accessors.
        ["flags", name] => parsed.flags.get(*name).map(FlagValue::to_json),
        ["flags_list", name] => match parsed.flags.get(*name)? {
            FlagValue::String(s) => Some(JsonValue::Array(vec![JsonValue::String(s.clone())])),
            FlagValue::List(xs) => Some(JsonValue::Array(
                xs.iter().map(|s| JsonValue::String(s.clone())).collect(),
            )),
            FlagValue::Bool(_) => None,
        },
        ["flag_exists", name] => Some(JsonValue::Bool(parsed.flags.contains_key(*name))),
        ["positional", idx_str] => {
            let idx: usize = idx_str.parse().ok()?;
            parsed
                .positional
                .get(idx)
                .map(|s| JsonValue::String(s.clone()))
        }
        ["subcommands", idx_str] => {
            let idx: usize = idx_str.parse().ok()?;
            parsed
                .subcommands
                .get(idx)
                .map(|s| JsonValue::String(s.clone()))
        }
        _ => None,
    }
}

/// Normalize a sub-command token for matching / template rendering.
///
/// Applies two transformations so users can write rules canonically:
///
/// 1. Lower-case (`CREATE` → `create`).
/// 2. `kebab-to-snake` (`create-user` → `create_user`) — AWS and a few
///    other CLIs use kebab-case operations; rules in YAML should use the
///    snake form for consistency with tool names.
///
/// Other CLIs (gog, gh, stripe) don't use dashes in sub-commands, so this
/// is safe as a universal default.
pub fn normalize_subcommand(raw: &str) -> String {
    raw.to_ascii_lowercase().replace('-', "_")
}

/// Evaluate a FieldSpec: resolve its source, apply transforms, return the
/// final JSON value (or `None` if the field should be omitted).
pub fn eval_field_spec(spec: &FieldSpec, parsed: &ParsedCommand) -> Option<JsonValue> {
    // 1. Resolve source: `from:` beats `value:` beats nothing.
    let mut current: Option<JsonValue> = if let Some(ref path) = spec.from {
        resolve_source_path(path, parsed)
    } else {
        spec.value.as_ref().map(yaml_to_json)
    };

    // 2. join / first — only meaningful for array values.
    if let Some(ref sep) = spec.join {
        current = current.map(|v| match v {
            JsonValue::Array(xs) => {
                let joined = xs
                    .iter()
                    .map(|x| match x {
                        JsonValue::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(sep);
                JsonValue::String(joined)
            }
            other => other,
        });
    }
    if spec.first == Some(true) {
        current = current.map(|v| match v {
            JsonValue::Array(mut xs) => {
                if xs.is_empty() {
                    JsonValue::Null
                } else {
                    xs.swap_remove(0)
                }
            }
            other => other,
        });
    }

    // 3. Default if still missing (or explicitly null).
    if matches!(current, None | Some(JsonValue::Null)) {
        if let Some(ref d) = spec.default {
            current = Some(yaml_to_json(d));
        }
    }

    // 4. Type coercion (best-effort).
    if let Some(ref ty) = spec.value_type {
        if let Some(v) = current.take() {
            current = Some(coerce(ty, v));
        }
    }

    // `None` survives through → field omitted.
    current
}

/// Walk a YAML parameter tree, producing a JSON value ready to hand to
/// permit0's engine.
///
/// Distinguishing FieldSpecs from nested literal objects:
/// - A YAML mapping with ANY key from [`FIELD_SPEC_KEYS`] is treated as a
///   FieldSpec and evaluated via [`eval_field_spec`].
/// - Any other mapping is treated as a nested literal object — its
///   children are recursively evaluated with [`eval_parameters`].
/// - Scalars and sequences pass through as literals.
pub fn eval_parameters(tree: &YamlValue, parsed: &ParsedCommand) -> JsonValue {
    match tree {
        YamlValue::Null => JsonValue::Null,
        YamlValue::Bool(b) => JsonValue::Bool(*b),
        YamlValue::Number(n) => yaml_number_to_json(n),
        YamlValue::String(s) => JsonValue::String(s.clone()),
        YamlValue::Sequence(xs) => JsonValue::Array(
            xs.iter()
                .map(|item| eval_parameters(item, parsed))
                .collect(),
        ),
        YamlValue::Mapping(m) => {
            if is_field_spec(m) {
                match serde_yaml::from_value::<FieldSpec>(YamlValue::Mapping(m.clone())) {
                    Ok(spec) => eval_field_spec(&spec, parsed).unwrap_or(JsonValue::Null),
                    // Malformed FieldSpec — surface as null so the normalizer
                    // sees a missing field rather than a panic. The dispatcher
                    // caller can still inspect the parsed command for debugging.
                    Err(_) => JsonValue::Null,
                }
            } else {
                let mut out = serde_json::Map::new();
                for (k, v) in m {
                    if let Some(key) = k.as_str() {
                        let rendered = eval_parameters(v, parsed);
                        // Skip explicit nulls so downstream normalizers don't
                        // see `"subject": null` when a flag was omitted —
                        // which would count as "present but empty" and upset
                        // `required` checks.
                        if !rendered.is_null() {
                            out.insert(key.to_string(), rendered);
                        }
                    }
                }
                JsonValue::Object(out)
            }
        }
        YamlValue::Tagged(t) => eval_parameters(&t.value, parsed),
    }
}

/// Render a fallback tool-name template. Supports `{program}` and
/// `{subcommand.N}` placeholders; missing sub-commands become empty string.
///
/// Example: `"gog_{subcommand.0}_{subcommand.1}"` against subcommands
/// `["gmail","send"]` → `"gog_gmail_send"`.
pub fn render_tool_name_template(template: &str, parsed: &ParsedCommand) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            out.push(c);
            continue;
        }
        // Read until matching `}`.
        let mut key = String::new();
        let mut closed = false;
        while let Some(&n) = chars.peek() {
            chars.next();
            if n == '}' {
                closed = true;
                break;
            }
            key.push(n);
        }
        if !closed {
            // Unterminated `{...` — emit verbatim to help debugging.
            out.push('{');
            out.push_str(&key);
            continue;
        }
        out.push_str(&render_placeholder(&key, parsed));
    }
    out
}

fn render_placeholder(key: &str, parsed: &ParsedCommand) -> String {
    let trimmed = key.trim();
    let parts: Vec<&str> = trimmed.splitn(2, '.').collect();
    match parts.as_slice() {
        ["program"] => parsed.program.clone(),
        ["original"] => parsed.original.clone(),
        // Sub-commands in templates always use the normalized form so
        // fallback tool names like `gog_{subcommand.0}_{subcommand.1}` never
        // end up with kebab dashes from the raw command.
        ["subcommand", idx_str] | ["subcommands", idx_str] => idx_str
            .parse::<usize>()
            .ok()
            .and_then(|i| parsed.subcommands.get(i))
            .map(|s| normalize_subcommand(s))
            .unwrap_or_default(),
        ["positional", idx_str] => idx_str
            .parse::<usize>()
            .ok()
            .and_then(|i| parsed.positional.get(i).cloned())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

// ── helpers ──

fn is_field_spec(m: &serde_yaml::Mapping) -> bool {
    FIELD_SPEC_KEYS
        .iter()
        .any(|k| m.contains_key(YamlValue::String((*k).into())))
}

fn yaml_to_json(v: &YamlValue) -> JsonValue {
    match v {
        YamlValue::Null => JsonValue::Null,
        YamlValue::Bool(b) => JsonValue::Bool(*b),
        YamlValue::Number(n) => yaml_number_to_json(n),
        YamlValue::String(s) => JsonValue::String(s.clone()),
        YamlValue::Sequence(xs) => JsonValue::Array(xs.iter().map(yaml_to_json).collect()),
        YamlValue::Mapping(m) => {
            let mut o = serde_json::Map::new();
            for (k, v) in m {
                if let Some(key) = k.as_str() {
                    o.insert(key.to_string(), yaml_to_json(v));
                }
            }
            JsonValue::Object(o)
        }
        YamlValue::Tagged(t) => yaml_to_json(&t.value),
    }
}

fn yaml_number_to_json(n: &serde_yaml::Number) -> JsonValue {
    if let Some(i) = n.as_i64() {
        JsonValue::Number(i.into())
    } else if let Some(u) = n.as_u64() {
        JsonValue::Number(u.into())
    } else if let Some(f) = n.as_f64() {
        serde_json::Number::from_f64(f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null)
    } else {
        JsonValue::Null
    }
}

fn coerce(ty: &FieldType, v: JsonValue) -> JsonValue {
    match ty {
        FieldType::String => match v {
            JsonValue::String(_) => v,
            JsonValue::Number(n) => JsonValue::String(n.to_string()),
            JsonValue::Bool(b) => JsonValue::String(b.to_string()),
            _ => v,
        },
        FieldType::Int => match &v {
            JsonValue::Number(n) => {
                if n.is_i64() {
                    v
                } else if let Some(f) = n.as_f64() {
                    serde_json::Number::from_f64(f.trunc())
                        .and_then(|n| {
                            n.as_f64().and_then(|fx| {
                                let as_i = fx as i64;
                                if (as_i as f64 - fx).abs() < f64::EPSILON {
                                    Some(JsonValue::Number(as_i.into()))
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or(v)
                } else {
                    v
                }
            }
            JsonValue::String(s) => s
                .parse::<i64>()
                .map(|i| JsonValue::Number(i.into()))
                .unwrap_or(v),
            _ => v,
        },
        FieldType::Number => match &v {
            JsonValue::Number(_) => v,
            JsonValue::String(s) => {
                if let Ok(i) = s.parse::<i64>() {
                    JsonValue::Number(i.into())
                } else if let Ok(f) = s.parse::<f64>() {
                    serde_json::Number::from_f64(f)
                        .map(JsonValue::Number)
                        .unwrap_or(v)
                } else {
                    v
                }
            }
            _ => v,
        },
        FieldType::Bool => match &v {
            JsonValue::Bool(_) => v,
            JsonValue::String(s) => match s.to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => JsonValue::Bool(true),
                "false" | "no" | "0" => JsonValue::Bool(false),
                _ => v,
            },
            _ => v,
        },
        FieldType::List => match v {
            JsonValue::Array(_) => v,
            other => JsonValue::Array(vec![other]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsed::{FlagValue, ParsedCommand};
    use std::collections::HashMap;

    fn fixture() -> ParsedCommand {
        let mut flags: HashMap<String, FlagValue> = HashMap::new();
        flags.insert("to".into(), FlagValue::String("alice@acme.com".into()));
        flags.insert("subject".into(), FlagValue::String("Hi".into()));
        flags.insert(
            "recipients".into(),
            FlagValue::List(vec!["alice@a.com".into(), "bob@b.com".into()]),
        );
        flags.insert("draft".into(), FlagValue::Bool(true));
        flags.insert("amount".into(), FlagValue::String("5000".into()));
        ParsedCommand {
            original: "gog gmail send --to alice@acme.com".into(),
            program: "gog".into(),
            subcommands: vec!["gmail".into(), "send".into()],
            positional: vec!["arg0".into(), "arg1".into()],
            flags,
        }
    }

    // resolve_source_path

    #[test]
    fn resolve_flag_string() {
        let p = fixture();
        assert_eq!(
            resolve_source_path("flags.to", &p).unwrap(),
            serde_json::json!("alice@acme.com")
        );
    }

    #[test]
    fn resolve_flag_list() {
        let p = fixture();
        assert_eq!(
            resolve_source_path("flags.recipients", &p).unwrap(),
            serde_json::json!(["alice@a.com", "bob@b.com"])
        );
    }

    #[test]
    fn resolve_flag_bool() {
        let p = fixture();
        assert_eq!(
            resolve_source_path("flags.draft", &p).unwrap(),
            serde_json::json!(true)
        );
    }

    #[test]
    fn resolve_flag_exists() {
        let p = fixture();
        assert_eq!(
            resolve_source_path("flag_exists.draft", &p).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            resolve_source_path("flag_exists.missing", &p).unwrap(),
            serde_json::json!(false)
        );
    }

    #[test]
    fn resolve_flags_list_wraps_singletons() {
        let p = fixture();
        assert_eq!(
            resolve_source_path("flags_list.to", &p).unwrap(),
            serde_json::json!(["alice@acme.com"])
        );
    }

    #[test]
    fn resolve_subcommands_and_positional() {
        let p = fixture();
        assert_eq!(
            resolve_source_path("subcommands.0", &p).unwrap(),
            serde_json::json!("gmail")
        );
        assert_eq!(
            resolve_source_path("positional.1", &p).unwrap(),
            serde_json::json!("arg1")
        );
    }

    #[test]
    fn resolve_whole_flags_map() {
        let p = fixture();
        let flags = resolve_source_path("flags", &p).unwrap();
        assert_eq!(flags["to"], "alice@acme.com");
        assert_eq!(flags["subject"], "Hi");
        assert_eq!(flags["draft"], true);
        // Lists appear verbatim.
        assert_eq!(flags["recipients"][0], "alice@a.com");
    }

    #[test]
    fn resolve_whole_positional_array() {
        let p = fixture();
        let pos = resolve_source_path("positional", &p).unwrap();
        assert_eq!(pos, serde_json::json!(["arg0", "arg1"]));
    }

    #[test]
    fn resolve_whole_subcommands_array() {
        let p = fixture();
        let sub = resolve_source_path("subcommands", &p).unwrap();
        assert_eq!(sub, serde_json::json!(["gmail", "send"]));
    }

    #[test]
    fn normalize_subcommand_kebab_and_case() {
        assert_eq!(normalize_subcommand("create-user"), "create_user");
        assert_eq!(normalize_subcommand("CREATE-USER"), "create_user");
        assert_eq!(normalize_subcommand("simple"), "simple");
        assert_eq!(normalize_subcommand(""), "");
    }

    #[test]
    fn template_normalizes_kebab_subcommand() {
        let mut p = fixture();
        p.subcommands = vec!["iam".into(), "create-user".into()];
        let out = render_tool_name_template("aws_{subcommand.0}_{subcommand.1}", &p);
        assert_eq!(out, "aws_iam_create_user");
    }

    #[test]
    fn resolve_missing_returns_none() {
        let p = fixture();
        assert!(resolve_source_path("flags.nonexistent", &p).is_none());
        assert!(resolve_source_path("positional.99", &p).is_none());
        assert!(resolve_source_path("gibberish", &p).is_none());
    }

    // eval_field_spec

    #[test]
    fn spec_from_flag() {
        let p = fixture();
        let spec = FieldSpec {
            from: Some("flags.to".into()),
            value: None,
            value_type: None,
            default: None,
            join: None,
            first: None,
        };
        assert_eq!(
            eval_field_spec(&spec, &p).unwrap(),
            serde_json::json!("alice@acme.com")
        );
    }

    #[test]
    fn spec_value_literal() {
        let p = fixture();
        let spec = FieldSpec {
            from: None,
            value: Some(serde_yaml::Value::String("POST".into())),
            value_type: None,
            default: None,
            join: None,
            first: None,
        };
        assert_eq!(
            eval_field_spec(&spec, &p).unwrap(),
            serde_json::json!("POST")
        );
    }

    #[test]
    fn spec_default_when_missing() {
        let p = fixture();
        let spec = FieldSpec {
            from: Some("flags.nonexistent".into()),
            value: None,
            value_type: None,
            default: Some(serde_yaml::Value::String("fallback".into())),
            join: None,
            first: None,
        };
        assert_eq!(
            eval_field_spec(&spec, &p).unwrap(),
            serde_json::json!("fallback")
        );
    }

    #[test]
    fn spec_join_list_to_csv() {
        let p = fixture();
        let spec = FieldSpec {
            from: Some("flags.recipients".into()),
            value: None,
            value_type: None,
            default: None,
            join: Some(",".into()),
            first: None,
        };
        assert_eq!(
            eval_field_spec(&spec, &p).unwrap(),
            serde_json::json!("alice@a.com,bob@b.com")
        );
    }

    #[test]
    fn spec_first_of_list() {
        let p = fixture();
        let spec = FieldSpec {
            from: Some("flags.recipients".into()),
            value: None,
            value_type: None,
            default: None,
            join: None,
            first: Some(true),
        };
        assert_eq!(
            eval_field_spec(&spec, &p).unwrap(),
            serde_json::json!("alice@a.com")
        );
    }

    #[test]
    fn spec_type_int_coerces_string_amount() {
        let p = fixture();
        let spec = FieldSpec {
            from: Some("flags.amount".into()),
            value: None,
            value_type: Some(FieldType::Int),
            default: None,
            join: None,
            first: None,
        };
        assert_eq!(eval_field_spec(&spec, &p).unwrap(), serde_json::json!(5000));
    }

    #[test]
    fn spec_type_bool_coerces_truthy() {
        let p = fixture();
        let spec = FieldSpec {
            from: None,
            value: Some(serde_yaml::Value::String("yes".into())),
            value_type: Some(FieldType::Bool),
            default: None,
            join: None,
            first: None,
        };
        assert_eq!(eval_field_spec(&spec, &p).unwrap(), serde_json::json!(true));
    }

    // eval_parameters

    #[test]
    fn tree_mixes_literals_and_specs() {
        let yaml = r#"
method: POST
url: "https://api.stripe.com/v1/charges"
body:
  amount: { from: flags.amount, type: int }
  currency: { from: flags.nonexistent, default: usd }
"#;
        let tree: YamlValue = serde_yaml::from_str(yaml).unwrap();
        let p = fixture();
        let rendered = eval_parameters(&tree, &p);
        assert_eq!(rendered["method"], "POST");
        assert_eq!(rendered["url"], "https://api.stripe.com/v1/charges");
        assert_eq!(rendered["body"]["amount"], 5000);
        assert_eq!(rendered["body"]["currency"], "usd");
    }

    #[test]
    fn tree_omits_missing_fields() {
        let yaml = r#"
to: { from: flags.to }
subject: { from: flags.nonexistent }
"#;
        let tree: YamlValue = serde_yaml::from_str(yaml).unwrap();
        let p = fixture();
        let rendered = eval_parameters(&tree, &p);
        assert_eq!(rendered["to"], "alice@acme.com");
        assert!(
            rendered.get("subject").is_none(),
            "missing fields are dropped"
        );
    }

    #[test]
    fn tree_plain_scalar_is_literal() {
        let tree: YamlValue = serde_yaml::from_str("hello world").unwrap();
        let p = fixture();
        let rendered = eval_parameters(&tree, &p);
        assert_eq!(rendered, serde_json::json!("hello world"));
    }

    // template rendering

    #[test]
    fn template_substitutes_subcommand() {
        let p = fixture();
        let out = render_tool_name_template("gog_{subcommand.0}_{subcommand.1}", &p);
        assert_eq!(out, "gog_gmail_send");
    }

    #[test]
    fn template_missing_placeholder_becomes_empty() {
        let p = fixture();
        let out = render_tool_name_template("x_{subcommand.99}_y", &p);
        assert_eq!(out, "x__y");
    }

    #[test]
    fn template_unterminated_placeholder_preserved() {
        let p = fixture();
        let out = render_tool_name_template("literal_{oops", &p);
        assert!(out.contains("{oops"));
    }
}
