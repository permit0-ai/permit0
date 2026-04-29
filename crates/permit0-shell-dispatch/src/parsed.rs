//! The intermediate [`ParsedCommand`] structure.
//!
//! A lightweight, parser-independent representation of a shell command after
//! tokenization + flag/positional extraction. Kept separate from the final
//! [`crate::DispatchedAction`] so tests and debuggers can inspect the
//! structural parse without caring which tool it dispatches to.

use std::collections::HashMap;

/// A single flag value. Most flags carry a string; a bare `--verbose` is
/// `Bool`; a repeated `--to alice --to bob` collapses to `List`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagValue {
    Bool(bool),
    String(String),
    List(Vec<String>),
}

impl FlagValue {
    /// Convert to a JSON value for downstream normalizer consumption.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Bool(b) => serde_json::Value::Bool(*b),
            Self::String(s) => serde_json::Value::String(s.clone()),
            Self::List(xs) => serde_json::Value::Array(
                xs.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        }
    }
}

/// The structural parse of a shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    /// Original command string as given — preserved for audit / debugging.
    pub original: String,
    /// Program name (first token), lower-cased.
    pub program: String,
    /// Sub-commands — positional arguments before any flag. Each parser
    /// decides how many of these it cares about (`gog service verb` takes
    /// two; `aws service operation` takes two; `bash` proper takes zero).
    pub subcommands: Vec<String>,
    /// Remaining positional arguments after the sub-commands but not part
    /// of any flag. E.g. `aws s3 cp SRC DST` → subcommands = ["s3", "cp"],
    /// positional = ["SRC", "DST"].
    pub positional: Vec<String>,
    /// Flag map (kebab-case source → snake_case key for JSON friendliness).
    pub flags: HashMap<String, FlagValue>,
}

impl ParsedCommand {
    /// Look up a flag's string value, falling back to `None` for booleans
    /// and lists.
    pub fn flag_str(&self, key: &str) -> Option<&str> {
        match self.flags.get(key)? {
            FlagValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Look up a flag as a string, accepting lists by joining or taking first.
    pub fn flag_first(&self, key: &str) -> Option<&str> {
        match self.flags.get(key)? {
            FlagValue::String(s) => Some(s.as_str()),
            FlagValue::List(xs) => xs.first().map(String::as_str),
            _ => None,
        }
    }

    /// Look up a flag's list-of-strings value (including singletons).
    pub fn flag_list(&self, key: &str) -> Option<Vec<String>> {
        match self.flags.get(key)? {
            FlagValue::String(s) => Some(vec![s.clone()]),
            FlagValue::List(xs) => Some(xs.clone()),
            _ => None,
        }
    }

    /// Build a JSON object from the flags, ready to hand to a permit0
    /// normalizer. Key collisions between flags and positional don't happen
    /// because positional goes under its own key.
    pub fn flags_to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        for (k, v) in &self.flags {
            m.insert(k.clone(), v.to_json());
        }
        m
    }
}

/// Given a flat token list starting from the post-program tokens, split
/// it into (subcommands before any flag, positional after sub-commands,
/// flag map).
///
/// `subcommand_depth` controls how many leading bare tokens are treated as
/// sub-commands — the rest become `positional`. If the token list has fewer
/// than `subcommand_depth` leading non-flag tokens, we take what's there.
///
/// Flag conventions supported:
/// - `--flag value` — two tokens.
/// - `--flag=value` — one token; value can contain `=`.
/// - `--flag` with no following value or followed by another flag → `Bool(true)`.
/// - `-f value` — single-dash short flags are treated like long flags here
///   (name = "f"). Multi-char short-flag clusters (`-abc`) are split into
///   individual bool flags.
/// - `--` — end-of-flags marker; everything after becomes positional.
/// - Repeated `--flag v1 --flag v2` collapses to `FlagValue::List(["v1","v2"])`.
///
/// Flag names are normalized: kebab-case `--user-name` → key `user_name`, so
/// rule YAML can reference them without escaping.
pub fn extract_structure(
    rest: &[String],
    subcommand_depth: usize,
) -> (Vec<String>, Vec<String>, HashMap<String, FlagValue>) {
    let mut subcommands = Vec::new();
    let mut positional = Vec::new();
    let mut flags: HashMap<String, FlagValue> = HashMap::new();

    // Collect leading bare tokens (non-flag) as sub-commands, up to depth.
    let mut idx = 0;
    while idx < rest.len() && subcommands.len() < subcommand_depth {
        let tok = &rest[idx];
        if tok.starts_with('-') {
            break;
        }
        subcommands.push(tok.clone());
        idx += 1;
    }

    let mut end_of_flags = false;
    while idx < rest.len() {
        let tok = &rest[idx];

        if end_of_flags {
            positional.push(tok.clone());
            idx += 1;
            continue;
        }

        if tok == "--" {
            end_of_flags = true;
            idx += 1;
            continue;
        }

        if let Some(stripped) = tok.strip_prefix("--") {
            // Long flag.
            let (key, value) = if let Some((k, v)) = stripped.split_once('=') {
                (k.to_string(), Some(v.to_string()))
            } else {
                (stripped.to_string(), None)
            };
            let key = normalize_flag_name(&key);

            let value = value.or_else(|| {
                // Peek the next token. If it starts with `-` (another flag)
                // or we're at the end, this flag is a boolean.
                rest.get(idx + 1).and_then(|next| {
                    if next.starts_with('-') {
                        None
                    } else {
                        idx += 1;
                        Some(next.clone())
                    }
                })
            });

            insert_flag(&mut flags, key, value);
        } else if let Some(short) = tok.strip_prefix('-') {
            // `-f value`  or  `-abc` (cluster of booleans).
            if short.len() == 1 {
                let key = normalize_flag_name(short);
                let value = rest.get(idx + 1).and_then(|next| {
                    if next.starts_with('-') {
                        None
                    } else {
                        idx += 1;
                        Some(next.clone())
                    }
                });
                insert_flag(&mut flags, key, value);
            } else {
                for c in short.chars() {
                    let key = normalize_flag_name(&c.to_string());
                    insert_flag(&mut flags, key, None);
                }
            }
        } else {
            // Positional after sub-commands.
            positional.push(tok.clone());
        }

        idx += 1;
    }

    (subcommands, positional, flags)
}

fn normalize_flag_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}

fn insert_flag(flags: &mut HashMap<String, FlagValue>, key: String, value: Option<String>) {
    let incoming = match value {
        Some(v) => FlagValue::String(v),
        None => FlagValue::Bool(true),
    };

    match flags.remove(&key) {
        None => {
            flags.insert(key, incoming);
        }
        // Repeated flag with a value → promote to list (or extend existing list).
        //
        // `incoming` is constructed locally above from `Option<String>`, so
        // it is always `Bool(true)` or `String(_)` — never `List(_)`.
        Some(existing) => match (existing, incoming) {
            (FlagValue::String(a), FlagValue::String(b)) => {
                flags.insert(key, FlagValue::List(vec![a, b]));
            }
            (FlagValue::List(mut xs), FlagValue::String(b)) => {
                xs.push(b);
                flags.insert(key, FlagValue::List(xs));
            }
            (FlagValue::String(a), FlagValue::Bool(_)) => {
                // `--foo X --foo` → keep the string form.
                flags.insert(key, FlagValue::String(a));
            }
            (FlagValue::List(xs), FlagValue::Bool(_)) => {
                flags.insert(key, FlagValue::List(xs));
            }
            (FlagValue::Bool(_), new) => {
                flags.insert(key, new);
            }
            (_, FlagValue::List(_)) => {
                // Unreachable by construction — `incoming` is always built
                // from `Option<String>` above, so it's only `Bool(true)` or
                // `String(_)`.
                unreachable!("incoming FlagValue is never a List");
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(ws: &[&str]) -> Vec<String> {
        ws.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn long_flag_with_value() {
        let (sub, pos, flags) = extract_structure(
            &words(&["gmail", "send", "--to", "alice@acme.com"]),
            2,
        );
        assert_eq!(sub, vec!["gmail", "send"]);
        assert!(pos.is_empty());
        assert_eq!(
            flags.get("to"),
            Some(&FlagValue::String("alice@acme.com".into()))
        );
    }

    #[test]
    fn long_flag_equals_form() {
        let (_, _, flags) =
            extract_structure(&words(&["gmail", "send", "--to=bob@acme.com"]), 2);
        assert_eq!(
            flags.get("to"),
            Some(&FlagValue::String("bob@acme.com".into()))
        );
    }

    #[test]
    fn bool_flag() {
        let (_, _, flags) = extract_structure(&words(&["pr", "create", "--draft"]), 2);
        assert_eq!(flags.get("draft"), Some(&FlagValue::Bool(true)));
    }

    #[test]
    fn kebab_is_normalized_to_snake() {
        let (_, _, flags) =
            extract_structure(&words(&["iam", "create-user", "--user-name", "alice"]), 2);
        assert_eq!(
            flags.get("user_name"),
            Some(&FlagValue::String("alice".into()))
        );
    }

    #[test]
    fn repeated_flag_becomes_list() {
        let (_, _, flags) = extract_structure(
            &words(&[
                "gmail", "send", "--to", "alice@x.com", "--to", "bob@y.com",
            ]),
            2,
        );
        assert_eq!(
            flags.get("to"),
            Some(&FlagValue::List(vec![
                "alice@x.com".into(),
                "bob@y.com".into()
            ]))
        );
    }

    #[test]
    fn end_of_flags_marker() {
        let (sub, pos, flags) = extract_structure(
            &words(&["s3", "cp", "--", "--weird-filename.txt", "dst.txt"]),
            2,
        );
        assert_eq!(sub, vec!["s3", "cp"]);
        assert_eq!(pos, vec!["--weird-filename.txt", "dst.txt"]);
        assert!(flags.is_empty());
    }

    #[test]
    fn positional_after_subcommands() {
        let (sub, pos, flags) =
            extract_structure(&words(&["s3", "cp", "src.txt", "s3://bucket/dst.txt"]), 2);
        assert_eq!(sub, vec!["s3", "cp"]);
        assert_eq!(pos, vec!["src.txt", "s3://bucket/dst.txt"]);
        assert!(flags.is_empty());
    }

    #[test]
    fn short_flag_cluster_is_booleans() {
        let (_, _, flags) = extract_structure(&words(&["pr", "list", "-vfq"]), 2);
        assert_eq!(flags.get("v"), Some(&FlagValue::Bool(true)));
        assert_eq!(flags.get("f"), Some(&FlagValue::Bool(true)));
        assert_eq!(flags.get("q"), Some(&FlagValue::Bool(true)));
    }

    #[test]
    fn short_flag_with_value() {
        let (_, _, flags) = extract_structure(&words(&["pr", "view", "-n", "42"]), 2);
        assert_eq!(flags.get("n"), Some(&FlagValue::String("42".into())));
    }

    #[test]
    fn subcommand_depth_zero_takes_no_subcommands() {
        let (sub, pos, _) =
            extract_structure(&words(&["cp", "src.txt", "dst.txt"]), 0);
        assert!(sub.is_empty());
        assert_eq!(pos, vec!["cp", "src.txt", "dst.txt"]);
    }

    #[test]
    fn flag_before_subcommand_stops_subcommand_collection() {
        // `--version` as the first token — no sub-commands collected.
        let (sub, _, flags) = extract_structure(&words(&["--version"]), 2);
        assert!(sub.is_empty());
        assert_eq!(flags.get("version"), Some(&FlagValue::Bool(true)));
    }
}
