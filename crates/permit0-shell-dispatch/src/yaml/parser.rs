//! [`YamlCommandParser`] — a [`CommandParser`] whose dispatch rules come
//! from YAML instead of hardcoded Rust.
//!
//! Each instance handles exactly ONE program. Multiple YAML files for the
//! same program are merged in load order via [`YamlCommandParser::merge`]:
//! rules from later files override rules with the same sub-command prefix
//! from earlier files, and otherwise accumulate.

use std::path::Path;

use thiserror::Error;

use crate::dispatcher::{CommandParser, Confidence, DispatchedAction};
use crate::parsed::{extract_structure, FlagValue, ParsedCommand};
use crate::tokenize::Tokens;

use super::eval::{eval_parameters, normalize_subcommand, render_tool_name_template};
use super::schema::{DispatcherYaml, DispatchRule, FallbackRule};

/// Errors from loading a dispatcher YAML file.
#[derive(Debug, Error)]
pub enum YamlParserError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("dispatcher for program '{program}' declares subcommand_depth={depth} but rule requires {needed}")]
    SubcommandDepthTooShallow {
        program: String,
        depth: usize,
        needed: usize,
    },

    #[error("cannot merge parsers for different programs: {a} vs {b}")]
    ProgramMismatch { a: String, b: String },
}

/// A CLI parser whose rules are loaded from YAML at runtime.
#[derive(Debug, Clone)]
pub struct YamlCommandParser {
    program: String,
    subcommand_depth: usize,
    rules: Vec<DispatchRule>,
    fallback: Option<FallbackRule>,
    parser_name: String,
}

impl YamlCommandParser {
    /// Build from an already-deserialized definition.
    pub fn from_def(def: DispatcherYaml) -> Result<Self, YamlParserError> {
        let program = def.program.trim().to_ascii_lowercase();
        let depth = def.subcommand_depth;

        // Validate every rule's match prefix fits in the declared depth.
        for rule in &def.dispatches {
            if rule.matcher.subcommands.len() > depth {
                return Err(YamlParserError::SubcommandDepthTooShallow {
                    program: program.clone(),
                    depth,
                    needed: rule.matcher.subcommands.len(),
                });
            }
        }

        Ok(Self {
            parser_name: format!("yaml:{program}"),
            program,
            subcommand_depth: depth,
            rules: def.dispatches,
            fallback: def.fallback,
        })
    }

    /// Parse a YAML source string and build the parser.
    pub fn from_yaml(src: &str) -> Result<Self, YamlParserError> {
        let def: DispatcherYaml = serde_yaml::from_str(src)?;
        Self::from_def(def)
    }

    /// Read a YAML file from disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, YamlParserError> {
        let p = path.as_ref();
        let contents = std::fs::read_to_string(p).map_err(|e| YamlParserError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        Self::from_yaml(&contents)
    }

    /// Program this parser handles.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Number of rules loaded (excluding fallback).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Whether a fallback rule is configured.
    pub fn has_fallback(&self) -> bool {
        self.fallback.is_some()
    }

    /// Merge another parser for the same program. Rules with the same
    /// sub-command prefix get replaced by the newer rule; other rules
    /// accumulate. The fallback, if any, is taken from the caller (the
    /// earlier-loaded parser) unless absent, in which case it's taken
    /// from `other`.
    pub fn merge(&mut self, other: YamlCommandParser) -> Result<(), YamlParserError> {
        if self.program != other.program {
            return Err(YamlParserError::ProgramMismatch {
                a: self.program.clone(),
                b: other.program,
            });
        }

        self.subcommand_depth = self.subcommand_depth.max(other.subcommand_depth);

        for new_rule in other.rules {
            // Replace existing rule with same sub-command prefix; else push.
            let existing = self
                .rules
                .iter_mut()
                .find(|r| r.matcher.subcommands == new_rule.matcher.subcommands);
            match existing {
                Some(r) => *r = new_rule,
                None => self.rules.push(new_rule),
            }
        }

        if self.fallback.is_none() {
            self.fallback = other.fallback;
        }

        Ok(())
    }

    /// Find the first rule whose sub-command prefix matches the parsed
    /// command's sub-commands.
    ///
    /// Comparison is done in the normalized form (lower-case + kebab→snake),
    /// so a rule written as `[iam, create_user]` matches a bash invocation
    /// of `aws iam create-user` — and vice versa.
    fn find_rule(&self, parsed: &ParsedCommand) -> Option<&DispatchRule> {
        let normalized: Vec<String> = parsed
            .subcommands
            .iter()
            .map(|s| normalize_subcommand(s))
            .collect();
        self.rules.iter().find(|r| {
            let needed = &r.matcher.subcommands;
            needed.len() <= normalized.len()
                && needed
                    .iter()
                    .enumerate()
                    .all(|(i, want)| normalized[i] == normalize_subcommand(want))
        })
    }
}

impl CommandParser for YamlCommandParser {
    fn name(&self) -> &str {
        &self.parser_name
    }

    fn can_parse(&self, program: &str) -> bool {
        program.eq_ignore_ascii_case(&self.program)
    }

    fn dispatch(&self, tokens: &Tokens) -> Option<DispatchedAction> {
        let (sub, pos, flags) = extract_structure(&tokens.rest, self.subcommand_depth);

        // Even the fallback needs at least the depth's worth of sub-commands
        // to be meaningful; if fewer, refuse to dispatch so the dispatcher
        // can fall through to the next parser.
        if sub.is_empty() {
            return None;
        }

        let original = format!("{} {}", self.program, tokens.rest.join(" "));
        let parsed = ParsedCommand {
            original,
            program: self.program.clone(),
            subcommands: sub,
            positional: pos,
            flags,
        };

        let (tool_name, params_tree, confidence) = if let Some(rule) = self.find_rule(&parsed) {
            (
                rule.tool_name.clone(),
                rule.parameters.clone(),
                parse_confidence(&rule.confidence),
            )
        } else if let Some(fb) = &self.fallback {
            (
                render_tool_name_template(&fb.tool_name, &parsed),
                fb.parameters.clone(),
                Confidence::Medium,
            )
        } else {
            return None;
        };

        let parameters = eval_parameters(&params_tree, &parsed);

        Some(DispatchedAction {
            // Parser name is an owned String; DispatchedAction.parser is
            // `&'static str` today. To avoid widening that lifetime, we
            // emit a fixed marker here — audit logs can look at
            // `tool_name` and `parsed.program` for the program-specific
            // context, which is richer anyway.
            parser: "yaml",
            parsed,
            tool_name,
            parameters,
            confidence,
        })
    }
}

fn parse_confidence(s: &Option<String>) -> Confidence {
    match s.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("low") => Confidence::Low,
        Some("medium") => Confidence::Medium,
        _ => Confidence::High,
    }
}

/// Omit-null-keyed helper: if a `ParsedCommand` has a flag value that's a
/// plain bool-true (from `--draft` with no value), `FlagValue::to_json`
/// produces `true`. The schema tests in `eval.rs` cover the rest.
#[allow(dead_code)]
fn _unused_reminder(_f: FlagValue) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::CommandParser;
    use crate::tokenize::Tokens;

    const GOG_GMAIL_YAML: &str = r#"
permit0_pack: "permit0/gmail"
program: gog
subcommand_depth: 2
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send
    parameters:
      to:
        from: flags.to
        join: ","
      subject: { from: flags.subject }
      body: { from: flags.body }
"#;

    #[test]
    fn loads_minimal_yaml() {
        let p = YamlCommandParser::from_yaml(GOG_GMAIL_YAML).unwrap();
        assert_eq!(p.program(), "gog");
        assert_eq!(p.rule_count(), 1);
    }

    #[test]
    fn dispatches_recognized_command() {
        let parser = YamlCommandParser::from_yaml(GOG_GMAIL_YAML).unwrap();
        let tokens = Tokens::parse("gog gmail send --to alice@acme.com --subject Hi").unwrap();
        let action = parser.dispatch(&tokens).unwrap();
        assert_eq!(action.tool_name, "gmail_send");
        assert_eq!(action.parameters["to"], "alice@acme.com");
        assert_eq!(action.parameters["subject"], "Hi");
    }

    #[test]
    fn repeated_flag_joined_via_spec() {
        let parser = YamlCommandParser::from_yaml(GOG_GMAIL_YAML).unwrap();
        let tokens =
            Tokens::parse("gog gmail send --to alice@x.com --to bob@y.com").unwrap();
        let action = parser.dispatch(&tokens).unwrap();
        assert_eq!(action.parameters["to"], "alice@x.com,bob@y.com");
    }

    #[test]
    fn unmatched_subcommand_returns_none_without_fallback() {
        let parser = YamlCommandParser::from_yaml(GOG_GMAIL_YAML).unwrap();
        let tokens = Tokens::parse("gog unknown verb --flag x").unwrap();
        assert!(parser.dispatch(&tokens).is_none());
    }

    #[test]
    fn fallback_fires_when_no_match() {
        let yaml = r#"
program: gog
subcommand_depth: 2
dispatches: []
fallback:
  tool_name: "gog_{subcommand.0}_{subcommand.1}"
  parameters:
    passthrough: { from: flags.x }
"#;
        let parser = YamlCommandParser::from_yaml(yaml).unwrap();
        let tokens = Tokens::parse("gog custom action --x 42").unwrap();
        let action = parser.dispatch(&tokens).unwrap();
        assert_eq!(action.tool_name, "gog_custom_action");
        assert_eq!(action.parameters["passthrough"], "42");
        // Fallback dispatches at Medium confidence.
        assert_eq!(action.confidence, Confidence::Medium);
    }

    #[test]
    fn merge_same_program_overrides_matching_rule() {
        let base = YamlCommandParser::from_yaml(
            r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send_v1
    parameters: {}
"#,
        )
        .unwrap();

        let overlay = YamlCommandParser::from_yaml(
            r#"
program: gog
dispatches:
  - match: { subcommands: [gmail, send] }
    tool_name: gmail_send_v2
    parameters: {}
  - match: { subcommands: [slack, post] }
    tool_name: slack_post
    parameters: {}
"#,
        )
        .unwrap();

        let mut merged = base;
        merged.merge(overlay).unwrap();
        assert_eq!(merged.rule_count(), 2);

        let t = Tokens::parse("gog gmail send").unwrap();
        let action = merged.dispatch(&t).unwrap();
        assert_eq!(action.tool_name, "gmail_send_v2");

        let t = Tokens::parse("gog slack post --channel general").unwrap();
        let action = merged.dispatch(&t).unwrap();
        assert_eq!(action.tool_name, "slack_post");
    }

    #[test]
    fn merge_program_mismatch_errors() {
        let mut a = YamlCommandParser::from_yaml("program: gog").unwrap();
        let b = YamlCommandParser::from_yaml("program: gh").unwrap();
        assert!(a.merge(b).is_err());
    }

    #[test]
    fn depth_too_shallow_rejected_at_load() {
        let yaml = r#"
program: gog
subcommand_depth: 1
dispatches:
  - match: { subcommands: [a, b, c] }
    tool_name: x
"#;
        let err = YamlCommandParser::from_yaml(yaml).unwrap_err();
        assert!(matches!(
            err,
            YamlParserError::SubcommandDepthTooShallow { .. }
        ));
    }

    #[test]
    fn can_parse_ignores_case() {
        let p = YamlCommandParser::from_yaml("program: Gog").unwrap();
        assert!(p.can_parse("gog"));
        assert!(p.can_parse("GOG"));
        assert!(!p.can_parse("aws"));
    }
}
