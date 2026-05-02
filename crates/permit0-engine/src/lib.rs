#![forbid(unsafe_code)]
#![doc = "Core permission engine orchestrator for permit0."]

pub mod bootstrap;
mod context;
mod engine;
mod error;
pub mod learning;

pub use context::PermissionCtx;
pub use engine::{DecisionSource, Engine, EngineBuilder, PermissionResult};
pub use error::EngineError;
pub use permit0_store::DecisionStage;
