//! YAML-driven command dispatchers.
//!
//! The split-level story:
//!
//! - [`schema`] — serde deserialize targets ([`DispatcherYaml`],
//!   [`DispatchRule`], [`FieldSpec`], [`FieldType`]).
//! - [`eval`] — evaluator that resolves source paths, processes FieldSpecs,
//!   and walks the parameter tree.
//! - [`parser`] — the [`YamlCommandParser`] that implements
//!   [`crate::CommandParser`].
//! - [`loader`] — helpers to scan filesystem layouts
//!   (`packs/*/dispatchers/*.yaml`) and produce a set of parsers ready to
//!   hand to [`crate::Dispatcher`].
//!
//! See `crates/permit0-shell-dispatch/README.md` (TODO) or the crate-level
//! doc in `lib.rs` for usage.

pub mod eval;
pub mod loader;
pub mod parser;
pub mod schema;

pub use eval::{eval_field_spec, eval_parameters, render_tool_name_template, resolve_source_path};
pub use loader::{LoadError, load_pack_dispatchers, load_yaml_dir};
pub use parser::{YamlCommandParser, YamlParserError};
pub use schema::{DispatchRule, DispatcherYaml, FallbackRule, FieldSpec, FieldType, MatchClause};
