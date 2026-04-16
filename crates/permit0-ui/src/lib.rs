#![forbid(unsafe_code)]
#![doc = "Web dashboard for audit log viewing and human approvals."]

pub mod approval;
pub mod auth;
pub mod dashboard_routes;
pub mod oidc;
pub mod pack_routes;
pub mod routes;
pub mod server;
pub mod state;

pub use approval::{ApprovalManager, HumanDecision, PendingApprovalSummary};
pub use auth::{ApiToken, Role, TokenStore};
pub use oidc::{OidcClient, OidcConfig, OidcState, RoleMapper, SessionStore};
pub use server::{ServerConfig, build_router, build_router_with_auth, build_router_with_oidc, create_app_state};
pub use state::AppState;
