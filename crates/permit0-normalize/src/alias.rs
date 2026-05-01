#![forbid(unsafe_code)]

//! Tool-name alias resolver.
//!
//! When an agent calls a tool whose name doesn't match any registered
//! normalizer (e.g. Google's official Gmail MCP exposes `create_label`
//! while permit0's pack normalizers key on `gmail_create_mailbox`), the
//! `AliasResolver` rewrites the bare tool name to a canonical one so the
//! normalizer registry can match.
//!
//! Two flavors of alias are supported:
//!
//! - **Flat**: `{ tool: "create_label", rewrite_as: "gmail_create_mailbox" }`
//! - **Conditional**: a `when:` block with `if`/`default` branches that
//!   choose the rewrite target based on a parameter value.
//!
//! Conditional aliases exist because some foreign tools overload one
//! name across multiple semantic actions. Gmail's `label_thread` adds
//! a label to a thread, but the *kind* of label changes the action
//! taxonomy: `STARRED` is `email.flag`, `SPAM` is `email.mark_spam`,
//! `TRASH` is `email.delete`, and arbitrary user labels are
//! `email.move`. A flat alias would mis-route the high-stakes cases
//! through whatever policy applies to the catch-all.
//!
//! ## YAML schema
//!
//! ```yaml
//! permit0_pack: "permit0/email"
//! aliases:
//!   - tool: create_label
//!     rewrite_as: gmail_create_mailbox
//!   - tool: label_thread
//!     when:
//!       - if: { param: labelIds, contains: SPAM }
//!         rewrite_as: gmail_mark_spam
//!       - if: { param: labelIds, contains: STARRED }
//!         rewrite_as: gmail_flag
//!       - default: gmail_move
//! ```
//!
//! Conditions are evaluated top-to-bottom; the first matching branch
//! wins. The optional `default` branch is the catch-all for
//! conditional entries.

use std::collections::HashMap;

use serde::Deserialize;

use crate::error::RegistryError;

/// Resolved alias action: either a flat rewrite or a conditional one.
#[derive(Debug)]
enum AliasAction {
    Flat(String),
    Conditional(Vec<WhenBranch>),
}

#[derive(Debug)]
struct WhenBranch {
    /// `None` for the catch-all `default` branch.
    condition: Option<Condition>,
    rewrite_as: String,
}

#[derive(Debug)]
struct Condition {
    param: String,
    matcher: Matcher,
}

#[derive(Debug)]
enum Matcher {
    /// Match if the param value is an array containing this scalar, or a
    /// string containing this substring.
    Contains(serde_json::Value),
}

impl Matcher {
    fn matches(&self, value: &serde_json::Value) -> bool {
        match self {
            Self::Contains(needle) => match value {
                serde_json::Value::Array(items) => items.iter().any(|v| v == needle),
                serde_json::Value::String(s) => match needle {
                    serde_json::Value::String(n) => s.contains(n.as_str()),
                    _ => false,
                },
                _ => false,
            },
        }
    }
}

/// Maps foreign tool names onto canonical ones the normalizer registry
/// knows about. The resolver runs *before* normalizer dispatch.
#[derive(Debug)]
pub struct AliasResolver {
    map: HashMap<String, AliasAction>,
}

impl AliasResolver {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Build a resolver from a YAML document. See module docs for the
    /// expected schema.
    pub fn from_yaml(yaml: &str) -> Result<Self, RegistryError> {
        let doc: AliasFile = serde_yaml::from_str(yaml)
            .map_err(|e| RegistryError::AliasParse(format!("yaml parse: {e}")))?;
        let mut resolver = Self::new();
        for entry in doc.aliases {
            let action = entry.compile()?;
            resolver.insert(entry.tool, action)?;
        }
        Ok(resolver)
    }

    /// Merge another resolver into this one. Errors on tool conflicts.
    pub fn merge(&mut self, other: AliasResolver) -> Result<(), RegistryError> {
        for (tool, action) in other.map {
            self.insert(tool, action)?;
        }
        Ok(())
    }

    fn insert(&mut self, tool: String, action: AliasAction) -> Result<(), RegistryError> {
        if self.map.contains_key(&tool) {
            let existing = match self.map.get(&tool).unwrap() {
                AliasAction::Flat(s) => s.clone(),
                AliasAction::Conditional(_) => "<conditional>".into(),
            };
            let new = match &action {
                AliasAction::Flat(s) => s.clone(),
                AliasAction::Conditional(_) => "<conditional>".into(),
            };
            return Err(RegistryError::AliasConflict {
                tool,
                existing,
                new,
            });
        }
        self.map.insert(tool, action);
        Ok(())
    }

    /// Resolve a tool name. Returns the rewrite target if the tool is
    /// aliased and any condition matches, else `None` (caller keeps the
    /// original name).
    ///
    /// `params` is the tool call's parameter object (`raw.parameters`),
    /// used to evaluate conditional `when:` clauses.
    pub fn resolve<'a>(
        &'a self,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> Option<&'a str> {
        match self.map.get(tool_name)? {
            AliasAction::Flat(target) => Some(target.as_str()),
            AliasAction::Conditional(branches) => {
                for branch in branches {
                    match &branch.condition {
                        None => return Some(branch.rewrite_as.as_str()),
                        Some(cond) => {
                            if let Some(value) = params.get(&cond.param) {
                                if cond.matcher.matches(value) {
                                    return Some(branch.rewrite_as.as_str());
                                }
                            }
                        }
                    }
                }
                None
            }
        }
    }

    /// Number of distinct tool names with aliases registered.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for AliasResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ── YAML schema (private deserialization types) ───────────────────────

#[derive(Debug, Deserialize)]
struct AliasFile {
    #[serde(default)]
    #[allow(dead_code)] // pack identifier; informational only
    permit0_pack: Option<String>,
    aliases: Vec<AliasEntry>,
}

#[derive(Debug, Deserialize)]
struct AliasEntry {
    tool: String,
    #[serde(default)]
    rewrite_as: Option<String>,
    #[serde(default)]
    when: Option<Vec<WhenClauseYaml>>,
}

impl AliasEntry {
    fn compile(&self) -> Result<AliasAction, RegistryError> {
        match (&self.rewrite_as, &self.when) {
            (Some(target), None) => Ok(AliasAction::Flat(target.clone())),
            (None, Some(branches)) => {
                if branches.is_empty() {
                    return Err(RegistryError::AliasParse(format!(
                        "alias '{}' has empty 'when' list",
                        self.tool
                    )));
                }
                let compiled: Result<Vec<_>, _> = branches
                    .iter()
                    .map(|b| b.compile(&self.tool))
                    .collect();
                Ok(AliasAction::Conditional(compiled?))
            }
            (Some(_), Some(_)) => Err(RegistryError::AliasParse(format!(
                "alias '{}' has both 'rewrite_as' and 'when' — pick one",
                self.tool
            ))),
            (None, None) => Err(RegistryError::AliasParse(format!(
                "alias '{}' has neither 'rewrite_as' nor 'when'",
                self.tool
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct WhenClauseYaml {
    #[serde(default, rename = "if")]
    condition: Option<ConditionYaml>,
    #[serde(default)]
    rewrite_as: Option<String>,
    #[serde(default)]
    default: Option<String>,
}

impl WhenClauseYaml {
    fn compile(&self, tool: &str) -> Result<WhenBranch, RegistryError> {
        match (&self.condition, &self.rewrite_as, &self.default) {
            (Some(cond), Some(target), None) => Ok(WhenBranch {
                condition: Some(cond.compile(tool)?),
                rewrite_as: target.clone(),
            }),
            (None, None, Some(target)) => Ok(WhenBranch {
                condition: None,
                rewrite_as: target.clone(),
            }),
            _ => Err(RegistryError::AliasParse(format!(
                "alias '{tool}' has malformed when clause — use either ('if' + 'rewrite_as') or 'default'"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConditionYaml {
    param: String,
    #[serde(default)]
    contains: Option<serde_yaml::Value>,
}

impl ConditionYaml {
    fn compile(&self, tool: &str) -> Result<Condition, RegistryError> {
        let matcher = match &self.contains {
            Some(v) => Matcher::Contains(yaml_to_json(v.clone())),
            None => {
                return Err(RegistryError::AliasParse(format!(
                    "alias '{tool}' condition for param '{}' has no matcher (expected 'contains')",
                    self.param
                )));
            }
        };
        Ok(Condition {
            param: self.param.clone(),
            matcher,
        })
    }
}

/// Convert a `serde_yaml::Value` into a `serde_json::Value` for matcher
/// storage. Yaml's tagged scalars are dropped — we only care about
/// strings, numbers, booleans, null, sequences and mappings.
fn yaml_to_json(v: serde_yaml::Value) -> serde_json::Value {
    match v {
        serde_yaml::Value::Null => serde_json::Value::Null,
        serde_yaml::Value::Bool(b) => serde_json::Value::Bool(b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml::Value::String(s) => serde_json::Value::String(s),
        serde_yaml::Value::Sequence(items) => {
            serde_json::Value::Array(items.into_iter().map(yaml_to_json).collect())
        }
        serde_yaml::Value::Mapping(m) => {
            let map = m
                .into_iter()
                .filter_map(|(k, v)| {
                    let key = match k {
                        serde_yaml::Value::String(s) => s,
                        _ => return None,
                    };
                    Some((key, yaml_to_json(v)))
                })
                .collect();
            serde_json::Value::Object(map)
        }
        serde_yaml::Value::Tagged(_) => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flat_alias_resolves() {
        let yaml = r#"
permit0_pack: "permit0/email"
aliases:
  - tool: create_label
    rewrite_as: gmail_create_mailbox
"#;
        let r = AliasResolver::from_yaml(yaml).unwrap();
        assert_eq!(
            r.resolve("create_label", &json!({})),
            Some("gmail_create_mailbox")
        );
        assert_eq!(r.resolve("nonexistent", &json!({})), None);
    }

    #[test]
    fn conditional_alias_picks_first_match() {
        let yaml = r#"
aliases:
  - tool: label_thread
    when:
      - if: { param: labelIds, contains: SPAM }
        rewrite_as: gmail_mark_spam
      - if: { param: labelIds, contains: STARRED }
        rewrite_as: gmail_flag
      - default: gmail_move
"#;
        let r = AliasResolver::from_yaml(yaml).unwrap();

        // Array contains SPAM → mark_spam.
        let spam = json!({ "labelIds": ["SPAM", "INBOX"] });
        assert_eq!(r.resolve("label_thread", &spam), Some("gmail_mark_spam"));

        // Array contains STARRED → flag.
        let star = json!({ "labelIds": ["STARRED"] });
        assert_eq!(r.resolve("label_thread", &star), Some("gmail_flag"));

        // Neither → falls through to default.
        let other = json!({ "labelIds": ["MyCustomLabel"] });
        assert_eq!(r.resolve("label_thread", &other), Some("gmail_move"));

        // Missing param → falls through to default (since default has no condition).
        assert_eq!(r.resolve("label_thread", &json!({})), Some("gmail_move"));
    }

    #[test]
    fn conditional_with_no_default_returns_none_on_miss() {
        let yaml = r#"
aliases:
  - tool: thing
    when:
      - if: { param: kind, contains: foo }
        rewrite_as: foo_canonical
"#;
        let r = AliasResolver::from_yaml(yaml).unwrap();
        // No condition matches, no default → no rewrite.
        assert_eq!(r.resolve("thing", &json!({"kind": "bar"})), None);
    }

    #[test]
    fn duplicate_tool_in_one_file_errors() {
        let yaml = r#"
aliases:
  - tool: create_label
    rewrite_as: gmail_create_mailbox
  - tool: create_label
    rewrite_as: outlook_create_mailbox
"#;
        let err = AliasResolver::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, RegistryError::AliasConflict { .. }));
    }

    #[test]
    fn entry_must_have_either_rewrite_or_when() {
        let yaml = r#"
aliases:
  - tool: half_baked
"#;
        assert!(matches!(
            AliasResolver::from_yaml(yaml).unwrap_err(),
            RegistryError::AliasParse(_)
        ));
    }

    #[test]
    fn entry_cannot_have_both_rewrite_and_when() {
        let yaml = r#"
aliases:
  - tool: confused
    rewrite_as: a
    when:
      - default: b
"#;
        assert!(matches!(
            AliasResolver::from_yaml(yaml).unwrap_err(),
            RegistryError::AliasParse(_)
        ));
    }

    #[test]
    fn empty_when_list_errors() {
        let yaml = r#"
aliases:
  - tool: empty
    when: []
"#;
        assert!(matches!(
            AliasResolver::from_yaml(yaml).unwrap_err(),
            RegistryError::AliasParse(_)
        ));
    }

    #[test]
    fn malformed_when_clause_errors() {
        // 'if' without 'rewrite_as'
        let yaml = r#"
aliases:
  - tool: bad
    when:
      - if: { param: x, contains: y }
"#;
        assert!(matches!(
            AliasResolver::from_yaml(yaml).unwrap_err(),
            RegistryError::AliasParse(_)
        ));
    }

    #[test]
    fn merge_two_resolvers() {
        let mut r = AliasResolver::from_yaml(
            r#"
aliases:
  - tool: a
    rewrite_as: aa
"#,
        )
        .unwrap();
        let other = AliasResolver::from_yaml(
            r#"
aliases:
  - tool: b
    rewrite_as: bb
"#,
        )
        .unwrap();
        r.merge(other).unwrap();
        assert_eq!(r.resolve("a", &json!({})), Some("aa"));
        assert_eq!(r.resolve("b", &json!({})), Some("bb"));
    }

    #[test]
    fn merge_conflict_errors() {
        let mut r = AliasResolver::from_yaml(
            r#"
aliases:
  - tool: a
    rewrite_as: aa
"#,
        )
        .unwrap();
        let other = AliasResolver::from_yaml(
            r#"
aliases:
  - tool: a
    rewrite_as: bb
"#,
        )
        .unwrap();
        assert!(matches!(
            r.merge(other).unwrap_err(),
            RegistryError::AliasConflict { .. }
        ));
    }

    #[test]
    fn matcher_string_substring_works() {
        let yaml = r#"
aliases:
  - tool: maybe_send
    when:
      - if: { param: command, contains: "swaks" }
        rewrite_as: swaks_send
      - default: bash_unknown
"#;
        let r = AliasResolver::from_yaml(yaml).unwrap();
        assert_eq!(
            r.resolve("maybe_send", &json!({"command": "swaks --to alice"})),
            Some("swaks_send")
        );
        assert_eq!(
            r.resolve("maybe_send", &json!({"command": "ls -la"})),
            Some("bash_unknown")
        );
    }
}
