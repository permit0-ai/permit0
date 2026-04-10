#![forbid(unsafe_code)]
#![doc = "Storage traits and implementations for permit0."]

mod memory;
mod sqlite;
mod traits;

pub use memory::InMemoryStore;
pub use sqlite::SqliteStore;
pub use traits::{Store, StoreError};
