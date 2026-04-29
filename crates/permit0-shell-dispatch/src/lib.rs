//! `permit0-shell-dispatch` — parse a bash command back into the semantic
//! tool call it's really making.
//!
//! When an agent runs `gog gmail send --to alice@acme.com`, the raw tool
//! call permit0 sees is `{"tool_name": "Bash", "parameters": {"command":
//! "gog gmail send ..."}}` — which would score as a generic
//! `process.shell`. That's a lost opportunity: the bash command is actually
//! an `email.send`, and the Gmail pack has much richer policy for that.
//!
//! This crate bridges the gap. It tokenizes the bash command, matches it
//! against a registry of CLI-specific dispatchers (loaded from YAML), and
//! — for recognized CLIs — emits a suggested [`permit0_types::RawToolCall`]
//! that re-routes through the correct pack.
//!
//! # Quick start
//!
//! ```no_run
//! use permit0_shell_dispatch::{Dispatcher, DispatchOutcome, UnknownCommandPolicy};
//!
//! let dispatcher = Dispatcher::new(UnknownCommandPolicy::Passthrough)
//!     .with_pack_dispatchers("packs")
//!     .unwrap();
//!
//! let outcome = dispatcher
//!     .dispatch("gog gmail send --to alice@acme.com --subject Hi --body x")
//!     .unwrap();
//!
//! match outcome {
//!     DispatchOutcome::Dispatched(action) => {
//!         assert_eq!(action.tool_name, "gmail_send");
//!         // Feed `action.suggested_tool_call()` back into the engine.
//!     }
//!     DispatchOutcome::Passthrough => {
//!         // Let the bash pack score it as process.shell.
//!     }
//!     DispatchOutcome::FlaggedUnknown(_) => {
//!         // Unknown command under FlagAsUnknown policy — treat with extra
//!         // scrutiny.
//!     }
//! }
//! ```
//!
//! # Design
//!
//! The crate is structured around three types:
//!
//! - [`Tokens`](tokenize::Tokens): shell-quote-aware tokenization of the
//!   command string, with env-prefix handling (`AWS_REGION=... aws ...`).
//! - [`ParsedCommand`]: lightweight structural parse (`program`,
//!   `subcommands`, `positional`, `flags`) — parser-agnostic and good for
//!   tests / logs.
//! - [`DispatchedAction`]: the structural parse plus the permit0-specific
//!   redirection (target tool name + synthesized parameters + confidence).
//!
//! Dispatchers are defined exclusively in YAML (`packs/<name>/dispatchers/*.yaml`);
//! see [`yaml`] for the DSL reference. Adding a new CLI is a YAML file, not a
//! code change + recompile.
//!
//! # What this is NOT
//!
//! - Not a full shell interpreter. It doesn't expand `$VAR`, execute
//!   subshells, follow `|` pipelines, or trace `&&` / `||` control flow.
//!   If you need those, run the command through a proper shell parser
//!   first and pass each sub-command separately.
//! - Not a normalizer. The output is a **suggestion** to re-submit to the
//!   permit0 engine, not a finalized `NormAction`. The engine's normalizer
//!   registry is still the source of truth for entity extraction and risk
//!   scoring.

pub mod dispatcher;
pub mod parsed;
pub mod tokenize;
pub mod yaml;

pub use dispatcher::{
    CommandParser, Confidence, DispatchOutcome, DispatchedAction, Dispatcher,
    UnknownCommandPolicy,
};
pub use parsed::{extract_structure, FlagValue, ParsedCommand};
pub use tokenize::{TokenizeError, Tokens};
pub use yaml::{
    load_pack_dispatchers, load_yaml_dir, LoadError, YamlCommandParser, YamlParserError,
};
