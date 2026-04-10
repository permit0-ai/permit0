#![forbid(unsafe_code)]

use std::sync::Arc;

use permit0_store::{AuditSink, Store};

use crate::approval::ApprovalManager;
use crate::auth::TokenStore;

/// Shared application state for the axum server.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    pub token_store: Arc<TokenStore>,
    pub approval_manager: Arc<ApprovalManager>,
}
