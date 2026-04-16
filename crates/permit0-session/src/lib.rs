#![forbid(unsafe_code)]
#![doc = "Session context and aggregation for permit0."]

pub mod amplifier;
pub mod block_rules;
pub mod context;
pub mod sqlite_storage;
pub mod storage;
pub mod types;

pub use amplifier::session_amplifier_score;
pub use block_rules::{SessionBlockResult, evaluate_session_block_rules};
pub use context::SessionContext;
pub use sqlite_storage::SqliteSessionStore;
pub use storage::InMemorySessionStore;
pub use types::{ActionRecord, SessionFilter};
