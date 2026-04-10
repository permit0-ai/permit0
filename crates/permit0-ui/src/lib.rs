#![forbid(unsafe_code)]
#![doc = "Web dashboard for audit log viewing and human approvals."]

pub mod approval;
pub mod auth;
pub mod routes;
pub mod server;
pub mod state;

pub use approval::{ApprovalManager, HumanDecision, PendingApprovalSummary};
pub use auth::{ApiToken, Role, TokenStore};
pub use server::{ServerConfig, build_router, build_router_with_auth, create_app_state};
pub use state::AppState;
