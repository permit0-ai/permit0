#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use permit0_store::{AuditSink, PolicyState};

use crate::approval::ApprovalManager;
use crate::auth::TokenStore;

/// Shared application state for the axum server.
///
/// `audit_sink` is the source of truth for the decision log and is
/// required: the dashboard reads stats, exports, calibration, and
/// failed-open windows from it.
#[derive(Clone)]
pub struct AppState {
    pub state: Arc<dyn PolicyState>,
    pub audit_sink: Arc<dyn AuditSink>,
    pub token_store: Arc<TokenStore>,
    pub approval_manager: Arc<ApprovalManager>,
    pub packs_dir: Option<PathBuf>,
    pub profiles_dir: Option<PathBuf>,
}
