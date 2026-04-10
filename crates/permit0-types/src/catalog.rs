#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Domains in the action catalog. Append-only — never rename or remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Email,
    Messages,
    Content,
    Calendar,
    Tasks,
    Files,
    Db,
    Crm,
    Payments,
    Legal,
    Iam,
    Secrets,
    Infra,
    Process,
    Network,
    Dev,
    Browser,
    Device,
    Ai,
    Unknown,
}

impl Domain {
    /// All valid verbs for this domain.
    pub fn verbs(self) -> &'static [Verb] {
        match self {
            Self::Email => &[
                Verb::Search, Verb::GetThread, Verb::Send, Verb::Reply,
                Verb::Forward, Verb::Draft, Verb::Label, Verb::Archive, Verb::Delete,
            ],
            Self::Messages => &[
                Verb::Send, Verb::PostChannel, Verb::SendDm,
                Verb::Search, Verb::React, Verb::Delete,
            ],
            Self::Content => &[Verb::PostSocial, Verb::UpdateCms, Verb::SendNewsletter],
            Self::Calendar => &[
                Verb::ListEvents, Verb::GetEvent, Verb::CreateEvent,
                Verb::UpdateEvent, Verb::DeleteEvent, Verb::Rsvp,
            ],
            Self::Tasks => &[
                Verb::Create, Verb::Assign, Verb::Complete,
                Verb::Update, Verb::Delete, Verb::Comment,
            ],
            Self::Files => &[
                Verb::List, Verb::Read, Verb::Write, Verb::Delete,
                Verb::Move, Verb::Copy, Verb::Share, Verb::Upload,
                Verb::Download, Verb::Export,
            ],
            Self::Db => &[
                Verb::Select, Verb::Insert, Verb::Update,
                Verb::Delete, Verb::Admin, Verb::Export, Verb::Backup,
            ],
            Self::Crm => &[
                Verb::SearchContacts, Verb::GetContact, Verb::CreateContact,
                Verb::UpdateContact, Verb::DeleteContact, Verb::CreateDeal,
                Verb::UpdateDeal, Verb::LogActivity, Verb::Export,
            ],
            Self::Payments => &[
                Verb::Charge, Verb::Refund, Verb::Transfer, Verb::GetBalance,
                Verb::ListTransactions, Verb::CreateInvoice,
                Verb::UpdatePaymentMethod, Verb::CreateSubscription,
            ],
            Self::Legal => &[Verb::SignDocument, Verb::SubmitFiling, Verb::AcceptTerms],
            Self::Iam => &[
                Verb::ListUsers, Verb::CreateUser, Verb::UpdateUser,
                Verb::DeleteUser, Verb::AssignRole, Verb::RevokeRole,
                Verb::ResetPassword, Verb::GenerateApiKey,
            ],
            Self::Secrets => &[Verb::Read, Verb::Create, Verb::Rotate],
            Self::Infra => &[
                Verb::ListResources, Verb::CreateResource, Verb::ModifyResource,
                Verb::TerminateResource, Verb::Scale, Verb::ModifyNetwork,
            ],
            Self::Process => &[
                Verb::Shell, Verb::RunScript, Verb::DockerRun, Verb::LambdaInvoke,
            ],
            Self::Network => &[Verb::HttpGet, Verb::HttpPost, Verb::WebhookSend],
            Self::Dev => &[
                Verb::GetRepo, Verb::ListIssues, Verb::CreateIssue,
                Verb::CreatePr, Verb::MergePr, Verb::PushCode,
                Verb::Deploy, Verb::RunPipeline, Verb::CreateRelease,
            ],
            Self::Browser => &[
                Verb::Navigate, Verb::Click, Verb::FillForm,
                Verb::SubmitForm, Verb::Screenshot, Verb::Download, Verb::ExecuteJs,
            ],
            Self::Device => &[
                Verb::Unlock, Verb::Lock, Verb::CameraEnable,
                Verb::CameraDisable, Verb::Move,
            ],
            Self::Ai => &[Verb::Prompt, Verb::Embed, Verb::FineTune],
            Self::Unknown => &[Verb::Unclassified],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Messages => "messages",
            Self::Content => "content",
            Self::Calendar => "calendar",
            Self::Tasks => "tasks",
            Self::Files => "files",
            Self::Db => "db",
            Self::Crm => "crm",
            Self::Payments => "payments",
            Self::Legal => "legal",
            Self::Iam => "iam",
            Self::Secrets => "secrets",
            Self::Infra => "infra",
            Self::Process => "process",
            Self::Network => "network",
            Self::Dev => "dev",
            Self::Browser => "browser",
            Self::Device => "device",
            Self::Ai => "ai",
            Self::Unknown => "unknown",
        }
    }

    /// Parse from string. Returns `None` for unknown domain names.
    pub fn parse(s: &str) -> Option<Self> {
        ALL_DOMAINS.iter().find(|d| d.as_str() == s).copied()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verbs in the action catalog. Append-only — never rename or remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    // ── email ──
    Search,
    GetThread,
    Send,
    Reply,
    Forward,
    Draft,
    Label,
    Archive,
    Delete,
    // ── messages ──
    PostChannel,
    SendDm,
    React,
    // ── content ──
    PostSocial,
    UpdateCms,
    SendNewsletter,
    // ── calendar ──
    ListEvents,
    GetEvent,
    CreateEvent,
    UpdateEvent,
    DeleteEvent,
    Rsvp,
    // ── tasks ──
    Create,
    Assign,
    Complete,
    Update,
    Comment,
    // ── files ──
    List,
    Read,
    Write,
    Move,
    Copy,
    Share,
    Upload,
    Download,
    Export,
    // ── db ──
    Select,
    Insert,
    Admin,
    Backup,
    // ── crm ──
    SearchContacts,
    GetContact,
    CreateContact,
    UpdateContact,
    DeleteContact,
    CreateDeal,
    UpdateDeal,
    LogActivity,
    // ── payments ──
    Charge,
    Refund,
    Transfer,
    GetBalance,
    ListTransactions,
    CreateInvoice,
    UpdatePaymentMethod,
    CreateSubscription,
    // ── legal ──
    SignDocument,
    SubmitFiling,
    AcceptTerms,
    // ── iam ──
    ListUsers,
    CreateUser,
    UpdateUser,
    DeleteUser,
    AssignRole,
    RevokeRole,
    ResetPassword,
    GenerateApiKey,
    // ── secrets ──
    Rotate,
    // ── infra ──
    ListResources,
    CreateResource,
    ModifyResource,
    TerminateResource,
    Scale,
    ModifyNetwork,
    // ── process ──
    Shell,
    RunScript,
    DockerRun,
    LambdaInvoke,
    // ── network ──
    HttpGet,
    HttpPost,
    WebhookSend,
    // ── dev ──
    GetRepo,
    ListIssues,
    CreateIssue,
    CreatePr,
    MergePr,
    PushCode,
    Deploy,
    RunPipeline,
    CreateRelease,
    // ── browser ──
    Navigate,
    Click,
    FillForm,
    SubmitForm,
    Screenshot,
    ExecuteJs,
    // ── device ──
    Unlock,
    Lock,
    CameraEnable,
    CameraDisable,
    // ── ai ──
    Prompt,
    Embed,
    FineTune,
    // ── unknown ──
    Unclassified,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::GetThread => "get_thread",
            Self::Send => "send",
            Self::Reply => "reply",
            Self::Forward => "forward",
            Self::Draft => "draft",
            Self::Label => "label",
            Self::Archive => "archive",
            Self::Delete => "delete",
            Self::PostChannel => "post_channel",
            Self::SendDm => "send_dm",
            Self::React => "react",
            Self::PostSocial => "post_social",
            Self::UpdateCms => "update_cms",
            Self::SendNewsletter => "send_newsletter",
            Self::ListEvents => "list_events",
            Self::GetEvent => "get_event",
            Self::CreateEvent => "create_event",
            Self::UpdateEvent => "update_event",
            Self::DeleteEvent => "delete_event",
            Self::Rsvp => "rsvp",
            Self::Create => "create",
            Self::Assign => "assign",
            Self::Complete => "complete",
            Self::Update => "update",
            Self::Comment => "comment",
            Self::List => "list",
            Self::Read => "read",
            Self::Write => "write",
            Self::Move => "move",
            Self::Copy => "copy",
            Self::Share => "share",
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Export => "export",
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Admin => "admin",
            Self::Backup => "backup",
            Self::SearchContacts => "search_contacts",
            Self::GetContact => "get_contact",
            Self::CreateContact => "create_contact",
            Self::UpdateContact => "update_contact",
            Self::DeleteContact => "delete_contact",
            Self::CreateDeal => "create_deal",
            Self::UpdateDeal => "update_deal",
            Self::LogActivity => "log_activity",
            Self::Charge => "charge",
            Self::Refund => "refund",
            Self::Transfer => "transfer",
            Self::GetBalance => "get_balance",
            Self::ListTransactions => "list_transactions",
            Self::CreateInvoice => "create_invoice",
            Self::UpdatePaymentMethod => "update_payment_method",
            Self::CreateSubscription => "create_subscription",
            Self::SignDocument => "sign_document",
            Self::SubmitFiling => "submit_filing",
            Self::AcceptTerms => "accept_terms",
            Self::ListUsers => "list_users",
            Self::CreateUser => "create_user",
            Self::UpdateUser => "update_user",
            Self::DeleteUser => "delete_user",
            Self::AssignRole => "assign_role",
            Self::RevokeRole => "revoke_role",
            Self::ResetPassword => "reset_password",
            Self::GenerateApiKey => "generate_api_key",
            Self::Rotate => "rotate",
            Self::ListResources => "list_resources",
            Self::CreateResource => "create_resource",
            Self::ModifyResource => "modify_resource",
            Self::TerminateResource => "terminate_resource",
            Self::Scale => "scale",
            Self::ModifyNetwork => "modify_network",
            Self::Shell => "shell",
            Self::RunScript => "run_script",
            Self::DockerRun => "docker_run",
            Self::LambdaInvoke => "lambda_invoke",
            Self::HttpGet => "http_get",
            Self::HttpPost => "http_post",
            Self::WebhookSend => "webhook_send",
            Self::GetRepo => "get_repo",
            Self::ListIssues => "list_issues",
            Self::CreateIssue => "create_issue",
            Self::CreatePr => "create_pr",
            Self::MergePr => "merge_pr",
            Self::PushCode => "push_code",
            Self::Deploy => "deploy",
            Self::RunPipeline => "run_pipeline",
            Self::CreateRelease => "create_release",
            Self::Navigate => "navigate",
            Self::Click => "click",
            Self::FillForm => "fill_form",
            Self::SubmitForm => "submit_form",
            Self::Screenshot => "screenshot",
            Self::ExecuteJs => "execute_js",
            Self::Unlock => "unlock",
            Self::Lock => "lock",
            Self::CameraEnable => "camera_enable",
            Self::CameraDisable => "camera_disable",
            Self::Prompt => "prompt",
            Self::Embed => "embed",
            Self::FineTune => "fine_tune",
            Self::Unclassified => "unclassified",
        }
    }

    /// Parse from string. Returns `None` for unknown verb names.
    pub fn parse(s: &str) -> Option<Self> {
        ALL_VERBS.iter().find(|v| v.as_str() == s).copied()
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated `domain.verb` pair from the action catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionType {
    pub domain: Domain,
    pub verb: Verb,
}

impl ActionType {
    /// Create a new ActionType, validating that the verb belongs to the domain.
    pub fn new(domain: Domain, verb: Verb) -> Result<Self, CatalogError> {
        if domain.verbs().contains(&verb) {
            Ok(Self { domain, verb })
        } else {
            Err(CatalogError::InvalidCombination { domain, verb })
        }
    }

    /// The `domain.verb` string form (e.g. "payments.charge").
    pub fn as_action_str(&self) -> String {
        format!("{}.{}", self.domain, self.verb)
    }

    /// Parse from a `domain.verb` string (e.g. "payments.charge").
    pub fn parse(s: &str) -> Result<Self, CatalogError> {
        let (domain_str, verb_str) = s.split_once('.').ok_or_else(|| {
            CatalogError::ParseError(format!("expected 'domain.verb', got '{s}'"))
        })?;
        let domain = Domain::parse(domain_str).ok_or_else(|| {
            CatalogError::UnknownDomain(domain_str.to_string())
        })?;
        let verb = Verb::parse(verb_str).ok_or_else(|| {
            CatalogError::UnknownVerb(verb_str.to_string())
        })?;
        Self::new(domain, verb)
    }

    /// The fallback action type for unrecognized tools.
    pub const UNKNOWN: Self = Self {
        domain: Domain::Unknown,
        verb: Verb::Unclassified,
    };
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.domain, self.verb)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum CatalogError {
    #[error("invalid combination: verb '{verb}' is not valid for domain '{domain}'")]
    InvalidCombination { domain: Domain, verb: Verb },
    #[error("unknown domain: '{0}'")]
    UnknownDomain(String),
    #[error("unknown verb: '{0}'")]
    UnknownVerb(String),
    #[error("parse error: {0}")]
    ParseError(String),
}

/// All domains in the catalog.
pub const ALL_DOMAINS: &[Domain] = &[
    Domain::Email,
    Domain::Messages,
    Domain::Content,
    Domain::Calendar,
    Domain::Tasks,
    Domain::Files,
    Domain::Db,
    Domain::Crm,
    Domain::Payments,
    Domain::Legal,
    Domain::Iam,
    Domain::Secrets,
    Domain::Infra,
    Domain::Process,
    Domain::Network,
    Domain::Dev,
    Domain::Browser,
    Domain::Device,
    Domain::Ai,
    Domain::Unknown,
];

/// All verbs in the catalog (flat list, some shared across domains).
const ALL_VERBS: &[Verb] = &[
    Verb::Search, Verb::GetThread, Verb::Send, Verb::Reply, Verb::Forward,
    Verb::Draft, Verb::Label, Verb::Archive, Verb::Delete, Verb::PostChannel,
    Verb::SendDm, Verb::React, Verb::PostSocial, Verb::UpdateCms,
    Verb::SendNewsletter, Verb::ListEvents, Verb::GetEvent, Verb::CreateEvent,
    Verb::UpdateEvent, Verb::DeleteEvent, Verb::Rsvp, Verb::Create, Verb::Assign,
    Verb::Complete, Verb::Update, Verb::Comment, Verb::List, Verb::Read,
    Verb::Write, Verb::Move, Verb::Copy, Verb::Share, Verb::Upload,
    Verb::Download, Verb::Export, Verb::Select, Verb::Insert, Verb::Admin,
    Verb::Backup, Verb::SearchContacts, Verb::GetContact, Verb::CreateContact,
    Verb::UpdateContact, Verb::DeleteContact, Verb::CreateDeal, Verb::UpdateDeal,
    Verb::LogActivity, Verb::Charge, Verb::Refund, Verb::Transfer,
    Verb::GetBalance, Verb::ListTransactions, Verb::CreateInvoice,
    Verb::UpdatePaymentMethod, Verb::CreateSubscription, Verb::SignDocument,
    Verb::SubmitFiling, Verb::AcceptTerms, Verb::ListUsers, Verb::CreateUser,
    Verb::UpdateUser, Verb::DeleteUser, Verb::AssignRole, Verb::RevokeRole,
    Verb::ResetPassword, Verb::GenerateApiKey, Verb::Rotate,
    Verb::ListResources, Verb::CreateResource, Verb::ModifyResource,
    Verb::TerminateResource, Verb::Scale, Verb::ModifyNetwork, Verb::Shell,
    Verb::RunScript, Verb::DockerRun, Verb::LambdaInvoke, Verb::HttpGet,
    Verb::HttpPost, Verb::WebhookSend, Verb::GetRepo, Verb::ListIssues,
    Verb::CreateIssue, Verb::CreatePr, Verb::MergePr, Verb::PushCode,
    Verb::Deploy, Verb::RunPipeline, Verb::CreateRelease, Verb::Navigate,
    Verb::Click, Verb::FillForm, Verb::SubmitForm, Verb::Screenshot,
    Verb::ExecuteJs, Verb::Unlock, Verb::Lock, Verb::CameraEnable,
    Verb::CameraDisable, Verb::Prompt, Verb::Embed, Verb::FineTune,
    Verb::Unclassified,
];

/// All valid `ActionType` entries in the catalog.
pub fn all_action_types() -> Vec<ActionType> {
    ALL_DOMAINS
        .iter()
        .flat_map(|d| d.verbs().iter().map(move |v| ActionType { domain: *d, verb: *v }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_action_type() {
        let at = ActionType::parse("payments.charge").unwrap();
        assert_eq!(at.domain, Domain::Payments);
        assert_eq!(at.verb, Verb::Charge);
        assert_eq!(at.as_action_str(), "payments.charge");
    }

    #[test]
    fn parse_invalid_combination() {
        // "charge" is not a valid verb for "email"
        let err = ActionType::parse("email.charge");
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            CatalogError::InvalidCombination { .. }
        ));
    }

    #[test]
    fn parse_unknown_domain() {
        let err = ActionType::parse("foobar.send");
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), CatalogError::UnknownDomain(_)));
    }

    #[test]
    fn parse_unknown_verb() {
        let err = ActionType::parse("email.explode");
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), CatalogError::UnknownVerb(_)));
    }

    #[test]
    fn parse_no_dot() {
        let err = ActionType::parse("nodot");
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), CatalogError::ParseError(_)));
    }

    #[test]
    fn unknown_action_type_constant() {
        assert_eq!(ActionType::UNKNOWN.domain, Domain::Unknown);
        assert_eq!(ActionType::UNKNOWN.verb, Verb::Unclassified);
        assert_eq!(ActionType::UNKNOWN.as_action_str(), "unknown.unclassified");
    }

    #[test]
    fn all_domain_verbs_are_valid_combinations() {
        for domain in ALL_DOMAINS {
            for verb in domain.verbs() {
                assert!(
                    ActionType::new(*domain, *verb).is_ok(),
                    "{domain}.{verb} should be valid"
                );
            }
        }
    }

    #[test]
    fn all_action_types_count() {
        let all = all_action_types();
        // Count from the spec table
        let expected = ALL_DOMAINS.iter().map(|d| d.verbs().len()).sum::<usize>();
        assert_eq!(all.len(), expected);
        // Sanity: should be >100 entries
        assert!(all.len() > 100, "catalog should have >100 entries, got {}", all.len());
    }

    #[test]
    fn display_roundtrip() {
        for at in all_action_types() {
            let s = at.to_string();
            let parsed = ActionType::parse(&s).unwrap();
            assert_eq!(at, parsed, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn serde_roundtrip() {
        let at = ActionType::parse("dev.deploy").unwrap();
        let json = serde_json::to_string(&at).unwrap();
        let back: ActionType = serde_json::from_str(&json).unwrap();
        assert_eq!(at, back);
    }
}
