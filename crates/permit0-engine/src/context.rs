#![forbid(unsafe_code)]

use permit0_normalize::NormalizeCtx;
use permit0_session::SessionContext;

/// Context passed to `get_permission()` for each tool call evaluation.
pub struct PermissionCtx {
    /// Normalization context (org domain, extra fields).
    pub normalize_ctx: NormalizeCtx,
    /// Optional session context for session-aware scoring and block rules.
    pub session: Option<SessionContext>,
    /// What the agent was asked to do (for agent reviewer context).
    pub task_goal: Option<String>,
}

impl PermissionCtx {
    pub fn new(normalize_ctx: NormalizeCtx) -> Self {
        Self {
            normalize_ctx,
            session: None,
            task_goal: None,
        }
    }

    pub fn with_session(mut self, session: SessionContext) -> Self {
        self.session = Some(session);
        self
    }

    pub fn with_task_goal(mut self, goal: impl Into<String>) -> Self {
        self.task_goal = Some(goal.into());
        self
    }
}
