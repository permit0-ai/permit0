#![forbid(unsafe_code)]
#![doc = "YAML DSL parser, interpreter, and helpers for permit0 packs."]

pub mod eval;
pub mod helpers;
pub mod lockfile;
pub mod normalizer;
pub mod pack_loader;
pub mod pack_validate;
pub mod risk_executor;
pub mod schema;
pub mod validate;

pub use lockfile::{
    LockedFile, LockfileError, PACK_LOCKFILE_FILENAME, PACK_LOCKFILE_VERSION, PackLockfile,
    sha256_hex,
};
pub use pack_loader::{
    ALIASES_FILENAME, CHANNEL_MANIFEST_FILENAME, DiscoveryError, PACK_MANIFEST_FILENAME,
    discover_alias_yamls, discover_normalizer_yamls, discover_packs,
};
pub use pack_validate::{
    ALWAYS_HUMAN_ACTION_TYPES, PackViolation, ViolationCode, tool_pattern_matches,
    validate_channel_directories, validate_pack,
};
