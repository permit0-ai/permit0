//! The [`Dispatcher`] — a registry of [`CommandParser`]s that converts a raw
//! bash command string into either a [`DispatchedAction`] (recognized CLI)
//! or an explicit "unknown" outcome.
//!
//! The dispatcher is intentionally small. The heavy lifting lives in the
//! individual parsers; this module just:
//! - tokenizes the command once,
//! - offers each parser a peek at it,
//! - returns the first match, or applies the configured unknown-policy.

use permit0_types::RawToolCall;
use serde::{Deserialize, Serialize};

use crate::parsed::ParsedCommand;
use crate::tokenize::{TokenizeError, Tokens};

/// What the dispatcher does when no registered parser recognizes a command.
///
/// This is not a value-laden default: bash pack authors have to pick based
/// on their threat model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownCommandPolicy {
    /// The dispatcher returns [`DispatchOutcome::Passthrough`] — "don't
    /// know this; let the bash pack handle it as plain `process.shell`."
    ///
    /// Use when you trust the bash pack to score unrecognized commands
    /// correctly on their own (the common choice for interactive CLIs).
    Passthrough,

    /// The dispatcher returns [`DispatchOutcome::FlaggedUnknown`] with the
    /// parsed structure — "unrecognized; treat with extra suspicion."
    ///
    /// Use when unrecognized CLIs on the shell surface are themselves a
    /// signal (e.g. a locked-down agent sandbox with an allowlist of known
    /// programs).
    FlagAsUnknown,
}

impl Default for UnknownCommandPolicy {
    fn default() -> Self {
        Self::Passthrough
    }
}

/// The outcome of dispatching a shell command.
#[derive(Debug, Clone)]
pub enum DispatchOutcome {
    /// A parser recognized the command and produced a [`DispatchedAction`].
    Dispatched(DispatchedAction),

    /// No parser matched, and the policy is [`UnknownCommandPolicy::Passthrough`].
    /// The caller should let the bash pack handle the command normally.
    Passthrough,

    /// No parser matched, and the policy is [`UnknownCommandPolicy::FlagAsUnknown`].
    /// The parsed structure is included for audit / escalation.
    FlaggedUnknown(ParsedCommand),
}

impl DispatchOutcome {
    /// Convenience: return the dispatched action if matched, else `None`.
    pub fn action(&self) -> Option<&DispatchedAction> {
        match self {
            Self::Dispatched(a) => Some(a),
            _ => None,
        }
    }

    /// Convenience: return the suggested re-routed [`RawToolCall`] if any.
    pub fn suggested_tool_call(&self) -> Option<RawToolCall> {
        self.action().map(|a| a.suggested_tool_call())
    }
}

/// The result of a successful dispatch.
///
/// Carries both the lightweight structural parse (for debugging) and the
/// intended redirection (for permit0 re-routing).
#[derive(Debug, Clone)]
pub struct DispatchedAction {
    /// Which parser recognized the command (e.g. `"gog"`, `"gh"`).
    pub parser: &'static str,

    /// Structural parse of the command (for logging / debugging / tests).
    pub parsed: ParsedCommand,

    /// Tool name to route to when re-submitting to the permit0 engine.
    /// Must match the `match: tool: <name>` of some installed normalizer.
    pub tool_name: String,

    /// Parameters to pass to permit0 for normalizer matching and rule
    /// evaluation.
    pub parameters: serde_json::Value,

    /// Parser confidence. [`Confidence::High`] is the default for commands
    /// whose shape exactly matches a known signature; [`Confidence::Medium`]
    /// means "probably this but missing required data"; [`Confidence::Low`]
    /// is reserved for heuristic matches (not currently used).
    pub confidence: Confidence,
}

impl DispatchedAction {
    /// Build a [`RawToolCall`] ready for [`permit0_engine::Engine::get_permission`].
    pub fn suggested_tool_call(&self) -> RawToolCall {
        RawToolCall {
            tool_name: self.tool_name.clone(),
            parameters: self.parameters.clone(),
            metadata: Default::default(),
        }
    }
}

/// Confidence levels for a dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Recognizer for a specific CLI tool.
///
/// Each parser owns a "program name" (usually hard-coded — `"gog"`, `"gh"`,
/// `"aws"`). When the dispatcher sees a command whose first token matches,
/// the parser is asked to convert it into a [`DispatchedAction`]. Parsers
/// are tried in registration order; the first match wins.
pub trait CommandParser: Send + Sync {
    /// A stable human-readable name for this parser. Used in audit logs.
    ///
    /// Returning `&str` (not `&'static str`) so YAML-loaded parsers can
    /// carry an owned name.
    fn name(&self) -> &str;

    /// Returns `true` if this parser handles the given program name.
    ///
    /// The name is already lower-cased by the tokenizer.
    fn can_parse(&self, program: &str) -> bool;

    /// Convert a matched token stream into a [`DispatchedAction`].
    ///
    /// Returning `None` means the parser recognized the program but the
    /// specific sub-command / flag combo isn't mapped — the dispatcher will
    /// fall through to the next parser or apply the unknown policy.
    fn dispatch(&self, tokens: &Tokens) -> Option<DispatchedAction>;
}

/// The dispatcher itself — holds a list of parsers and an unknown-policy.
///
/// Construct with [`Dispatcher::new`] + [`Dispatcher::with_parser`], or use
/// the curated [`Dispatcher::with_defaults`] to get all four built-in
/// parsers at once.
pub struct Dispatcher {
    parsers: Vec<Box<dyn CommandParser>>,
    unknown_policy: UnknownCommandPolicy,
}

impl Dispatcher {
    pub fn new(unknown_policy: UnknownCommandPolicy) -> Self {
        Self {
            parsers: Vec::new(),
            unknown_policy,
        }
    }

    /// Register a parser. Parsers are tried in insertion order.
    pub fn with_parser<P: CommandParser + 'static>(mut self, parser: P) -> Self {
        self.parsers.push(Box::new(parser));
        self
    }

    /// Install a parser defined inline as a YAML string.
    ///
    /// ```
    /// # use permit0_shell_dispatch::{Dispatcher, UnknownCommandPolicy};
    /// let d = Dispatcher::new(UnknownCommandPolicy::Passthrough)
    ///     .with_yaml_str(r#"
    ///         program: myorg
    ///         dispatches:
    ///           - match: { subcommands: [service, verb] }
    ///             tool_name: myorg_service_verb
    ///             parameters: {}
    ///     "#)
    ///     .unwrap();
    /// assert!(d.dispatch("myorg service verb --x 1").is_ok());
    /// ```
    pub fn with_yaml_str(
        mut self,
        yaml: &str,
    ) -> Result<Self, crate::yaml::YamlParserError> {
        let parser = crate::yaml::YamlCommandParser::from_yaml(yaml)?;
        self.parsers.push(Box::new(parser));
        Ok(self)
    }

    /// Install a parser defined in a YAML file.
    pub fn with_yaml_file<P: AsRef<std::path::Path>>(
        mut self,
        path: P,
    ) -> Result<Self, crate::yaml::YamlParserError> {
        let parser = crate::yaml::YamlCommandParser::from_file(path)?;
        self.parsers.push(Box::new(parser));
        Ok(self)
    }

    /// Scan `packs/<name>/dispatchers/*.yaml` under `packs_dir` and install
    /// one parser per declared `program:` — files declaring the same
    /// program are merged, so each pack can contribute its own slice of
    /// the rules for a shared CLI (every pack that ships a `gog` dispatcher
    /// lands in the same parser, for instance).
    ///
    /// Parsers are registered in alphabetic order of program name —
    /// deterministic and easy to debug. They go AFTER whatever parsers
    /// were already registered. Use [`Self::prepend_pack_dispatchers`] to
    /// insert them at the front when you want pack YAML to override
    /// parsers you manually wired in earlier (e.g. via [`Self::with_yaml_str`]).
    pub fn with_pack_dispatchers<P: AsRef<std::path::Path>>(
        mut self,
        packs_dir: P,
    ) -> Result<Self, crate::yaml::LoadError> {
        for parser in crate::yaml::load_pack_dispatchers(packs_dir)? {
            self.parsers.push(Box::new(parser));
        }
        Ok(self)
    }

    /// Like [`Self::with_pack_dispatchers`], but inserts the YAML-loaded
    /// parsers AT THE FRONT of the list so they take priority over any
    /// previously-registered parser for the same program.
    pub fn prepend_pack_dispatchers<P: AsRef<std::path::Path>>(
        mut self,
        packs_dir: P,
    ) -> Result<Self, crate::yaml::LoadError> {
        let mut yaml_parsers: Vec<Box<dyn CommandParser>> =
            crate::yaml::load_pack_dispatchers(packs_dir)?
                .into_iter()
                .map(|p| -> Box<dyn CommandParser> { Box::new(p) })
                .collect();
        yaml_parsers.append(&mut self.parsers);
        self.parsers = yaml_parsers;
        Ok(self)
    }

    /// Number of parsers currently registered. Useful for assertions in
    /// tests that verify loader behavior.
    pub fn parser_count(&self) -> usize {
        self.parsers.len()
    }

    /// Return the current unknown-command policy.
    pub fn unknown_policy(&self) -> UnknownCommandPolicy {
        self.unknown_policy
    }

    /// Dispatch a raw bash command string.
    pub fn dispatch(&self, command: &str) -> Result<DispatchOutcome, TokenizeError> {
        let tokens = Tokens::parse(command)?;

        for parser in &self.parsers {
            if !parser.can_parse(&tokens.program) {
                continue;
            }
            if let Some(action) = parser.dispatch(&tokens) {
                return Ok(DispatchOutcome::Dispatched(action));
            }
        }

        // No parser matched — apply policy.
        match self.unknown_policy {
            UnknownCommandPolicy::Passthrough => Ok(DispatchOutcome::Passthrough),
            UnknownCommandPolicy::FlagAsUnknown => {
                let parsed = ParsedCommand {
                    original: command.trim().to_string(),
                    program: tokens.program.clone(),
                    subcommands: Vec::new(),
                    positional: tokens.rest.clone(),
                    flags: Default::default(),
                };
                Ok(DispatchOutcome::FlaggedUnknown(parsed))
            }
        }
    }
}

impl Default for Dispatcher {
    /// An empty dispatcher with the default unknown-command policy
    /// ([`UnknownCommandPolicy::Passthrough`]). Call
    /// [`Dispatcher::with_pack_dispatchers`] to populate it with YAML
    /// dispatchers from `packs/<name>/dispatchers/`.
    fn default() -> Self {
        Self::new(UnknownCommandPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeParser;
    impl CommandParser for FakeParser {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn can_parse(&self, program: &str) -> bool {
            program == "fake"
        }
        fn dispatch(&self, tokens: &Tokens) -> Option<DispatchedAction> {
            Some(DispatchedAction {
                parser: "fake",
                parsed: ParsedCommand {
                    original: String::new(),
                    program: tokens.program.clone(),
                    subcommands: tokens.rest.clone(),
                    positional: Vec::new(),
                    flags: Default::default(),
                },
                tool_name: "fake_tool".into(),
                parameters: serde_json::json!({}),
                confidence: Confidence::High,
            })
        }
    }

    #[test]
    fn passthrough_on_unknown_program() {
        let d = Dispatcher::new(UnknownCommandPolicy::Passthrough).with_parser(FakeParser);
        let out = d.dispatch("real-tool do thing").unwrap();
        assert!(matches!(out, DispatchOutcome::Passthrough));
    }

    #[test]
    fn flag_as_unknown_on_unknown_program() {
        let d = Dispatcher::new(UnknownCommandPolicy::FlagAsUnknown).with_parser(FakeParser);
        let out = d.dispatch("real-tool do thing").unwrap();
        match out {
            DispatchOutcome::FlaggedUnknown(p) => {
                assert_eq!(p.program, "real-tool");
                assert!(p.positional.contains(&"do".to_string()));
            }
            other => panic!("expected FlaggedUnknown, got {other:?}"),
        }
    }

    #[test]
    fn first_match_wins() {
        let d = Dispatcher::new(UnknownCommandPolicy::Passthrough).with_parser(FakeParser);
        let out = d.dispatch("fake arg1 arg2").unwrap();
        let action = out.action().expect("dispatched");
        assert_eq!(action.parser, "fake");
        assert_eq!(action.tool_name, "fake_tool");
    }

    #[test]
    fn tokenize_error_propagates() {
        let d = Dispatcher::new(UnknownCommandPolicy::Passthrough);
        let result = d.dispatch(r#"unterminated "quote"#);
        assert!(result.is_err());
    }
}
