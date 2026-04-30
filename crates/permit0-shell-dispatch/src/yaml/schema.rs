//! YAML deserialization targets for dispatcher definitions.
//!
//! A dispatcher YAML file declares how to route a CLI's commands into
//! permit0's tool-name space. Example — `packs/gmail/dispatchers/gog.yaml`:
//!
//! ```yaml
//! permit0_pack: "permit0/gmail"
//! program: gog
//! subcommand_depth: 2
//!
//! dispatches:
//!   - match: { subcommands: [gmail, send] }
//!     tool_name: gmail_send
//!     parameters:
//!       to: { from: flags.to, join: "," }
//!       subject: { from: flags.subject }
//!       body: { from: flags.body }
//! ```
//!
//! One YAML file corresponds to one `program` (e.g. `gog`, `gh`). Multiple
//! YAML files CAN declare rules for the same program — the loader merges
//! them when building a single [`crate::yaml::YamlCommandParser`]. This
//! lets each pack ship only its own slice.

use serde::Deserialize;

/// Top-level dispatcher YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct DispatcherYaml {
    /// Pack identifier for audit (e.g. `"permit0/gmail"`). Not enforced.
    #[serde(default)]
    pub permit0_pack: Option<String>,

    /// CLI program name this file dispatches (e.g. `"gog"`, `"gh"`).
    pub program: String,

    /// How many leading bare tokens to treat as sub-commands.
    /// Defaults to 2, which matches every mainstream CLI's convention.
    #[serde(default = "default_subcommand_depth")]
    pub subcommand_depth: usize,

    /// Specific dispatch rules, tried in order.
    #[serde(default)]
    pub dispatches: Vec<DispatchRule>,

    /// Fallback rule when no `dispatches:` entry matches. If omitted, the
    /// parser returns `None` for unmatched sub-commands and the dispatcher
    /// falls through to the next parser (or the unknown-command policy).
    #[serde(default)]
    pub fallback: Option<FallbackRule>,
}

fn default_subcommand_depth() -> usize {
    2
}

/// A single (sub-commands → tool_name, parameters) dispatch rule.
#[derive(Debug, Clone, Deserialize)]
pub struct DispatchRule {
    /// Which sub-command prefix triggers this rule.
    #[serde(rename = "match")]
    pub matcher: MatchClause,

    /// The permit0 tool name to route to (matches a normalizer's
    /// `match: tool: <name>`).
    pub tool_name: String,

    /// Parameters to synthesize. Each leaf is either a plain literal or a
    /// [`crate::yaml::FieldSpec`] (a mapping with any of `from` / `value` /
    /// `type` / `default` / `join` / `first`). Nested mappings that *don't*
    /// look like a FieldSpec become nested literal objects.
    #[serde(default)]
    pub parameters: serde_yaml::Value,

    /// Confidence override (defaults to `high`).
    #[serde(default)]
    pub confidence: Option<String>,
}

/// A fallback that runs when no specific rule matches.
#[derive(Debug, Clone, Deserialize)]
pub struct FallbackRule {
    /// Template for the tool name. Supports `{program}`, `{subcommand.N}`
    /// placeholders — e.g. `"gog_{subcommand.0}_{subcommand.1}"`.
    pub tool_name: String,

    /// Parameters tree, same semantics as [`DispatchRule::parameters`].
    #[serde(default)]
    pub parameters: serde_yaml::Value,
}

/// The `match:` clause — currently only by sub-command prefix.
///
/// Declaring a match with `subcommands: [gmail, send]` says "the first
/// two sub-commands must be `gmail` and `send`". Length must be ≤
/// `subcommand_depth` (checked at load time).
#[derive(Debug, Clone, Deserialize)]
pub struct MatchClause {
    /// Exact sub-command prefix, lower-cased comparison.
    pub subcommands: Vec<String>,
}

/// A single parameter field spec, deserialized from mappings like
/// `{ from: flags.to, join: "," }`.
///
/// A mapping is treated as a `FieldSpec` (instead of a nested literal
/// object) iff at least one of these "spec keys" is present:
/// `from`, `value`, `type`, `default`, `join`, `first`. See
/// [`crate::yaml::eval`] for the detection rule.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldSpec {
    /// Source path, e.g. `"flags.to"`, `"positional.0"`, `"subcommands.1"`,
    /// `"program"`, `"original"`, `"flag_exists.draft"`, `"flags_list.to"`.
    #[serde(default)]
    pub from: Option<String>,

    /// Literal value (alternative to `from`).
    #[serde(default)]
    pub value: Option<serde_yaml::Value>,

    /// Type coercion hint; best-effort (falls back to string on failure).
    #[serde(default, rename = "type")]
    pub value_type: Option<FieldType>,

    /// Fallback value when `from` resolves to nothing.
    #[serde(default)]
    pub default: Option<serde_yaml::Value>,

    /// If source value is a list, join with this separator (→ string).
    #[serde(default)]
    pub join: Option<String>,

    /// If source value is a list, take the first element.
    #[serde(default)]
    pub first: Option<bool>,
}

/// Type coercions supported by `FieldSpec::type`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Int,
    Number,
    Bool,
    List,
}

/// The "spec keys" that distinguish a `FieldSpec` mapping from a nested
/// literal object. Kept centralized so `eval.rs` and any future helper
/// agree on the detection rule.
pub const FIELD_SPEC_KEYS: &[&str] = &["from", "value", "type", "default", "join", "first"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_dispatcher() {
        let yaml = r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send
    parameters:
      to: { from: flags.to }
"#;
        let def: DispatcherYaml = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.program, "gog");
        assert_eq!(def.subcommand_depth, 2);
        assert_eq!(def.dispatches.len(), 1);
        assert_eq!(def.dispatches[0].matcher.subcommands, vec!["gmail", "send"]);
    }

    #[test]
    fn with_fallback() {
        let yaml = r#"
program: gog
dispatches: []
fallback:
  tool_name: "gog_{subcommand.0}_{subcommand.1}"
  parameters:
    flags: { from: flags.*, default: {} }
"#;
        let def: DispatcherYaml = serde_yaml::from_str(yaml).unwrap();
        assert!(def.fallback.is_some());
        assert_eq!(
            def.fallback.unwrap().tool_name,
            "gog_{subcommand.0}_{subcommand.1}"
        );
    }

    #[test]
    fn field_type_deserialize() {
        let cases = [
            ("string", FieldType::String),
            ("int", FieldType::Int),
            ("number", FieldType::Number),
            ("bool", FieldType::Bool),
            ("list", FieldType::List),
        ];
        for (s, expected) in cases {
            let t: FieldType = serde_yaml::from_str(s).unwrap();
            assert_eq!(t, expected);
        }
    }
}
