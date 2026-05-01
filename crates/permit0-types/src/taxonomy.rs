#![forbid(unsafe_code)]

//! The action taxonomy — the authoritative `domain.verb` classification that
//! all norm actions must conform to.
//!
//! ## Domains
//!
//! Two tiers of detail in this taxonomy:
//!
//! - **`email`**: fully fleshed out (15 verbs), backed by real normalizers
//!   and risk rules in `packs/email/`.
//! - **All other domains**: declared as **placeholders** with a clean verb
//!   list. They have no normalizers or risk rules yet — the taxonomy defines
//!   the schema, future packs implement it.
//!
//! ## Verb design
//!
//! Generic verbs (`get`, `list`, `create`, `update`, `delete`) appear in
//! many domains. Disambiguation between resource types (e.g. `iam.create`
//! creating a user vs. a role) is handled via a `resource_type` entity in
//! the normalizer, not by exploding the verb space (avoid `create_user`,
//! `create_role`, `create_api_key`).
//!
//! The exception is `email`, which uses verb-level distinctions where the
//! semantics are different enough to warrant separate risk treatment
//! (e.g. `set_forwarding` is account takeover, very different from
//! `create_mailbox`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Domains in the action taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Email,
    Message,
    Social,
    Cms,
    Newsletter,
    Calendar,
    Task,
    File,
    Db,
    Crm,
    Payment,
    Legal,
    Iam,
    Secret,
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
            // ── EMAIL: fully fleshed (the only domain with normalizers + risk rules) ──
            Self::Email => &[
                Verb::Search,
                Verb::Read,
                Verb::ReadThread,
                Verb::ListMailboxes,
                Verb::Draft,
                Verb::ListDrafts,
                Verb::Send,
                Verb::MarkRead,
                Verb::Flag,
                Verb::Move,
                Verb::Archive,
                Verb::MarkSpam,
                Verb::Delete,
                Verb::CreateMailbox,
                Verb::SetForwarding,
                Verb::AddDelegate,
            ],

            // ── PLACEHOLDERS (verb skeleton only, no packs yet) ──
            Self::Message => &[
                Verb::PostChannel,
                Verb::SendDm,
                Verb::SendSms,
                Verb::Search,
                Verb::Get,
                Verb::React,
                Verb::Update,
                Verb::Delete,
            ],
            Self::Social => &[
                Verb::Post,
                Verb::Reply,
                Verb::Delete,
                Verb::Like,
                Verb::SendDm,
                Verb::Search,
            ],
            Self::Cms => &[
                Verb::Publish,
                Verb::Update,
                Verb::Unpublish,
                Verb::Schedule,
                Verb::Delete,
                Verb::List,
            ],
            Self::Newsletter => &[
                Verb::Send,
                Verb::Schedule,
                Verb::Draft,
                Verb::Update,
                Verb::Unsubscribe,
            ],
            Self::Calendar => &[
                Verb::List,
                Verb::Get,
                Verb::Create,
                Verb::Update,
                Verb::Delete,
                Verb::Rsvp,
            ],
            Self::Task => &[
                Verb::Create,
                Verb::Get,
                Verb::List,
                Verb::Update,
                Verb::Complete,
                Verb::Assign,
                Verb::Delete,
                Verb::Comment,
            ],
            Self::File => &[
                Verb::List,
                Verb::Get,
                Verb::Read,
                Verb::Create,
                Verb::Update,
                Verb::Delete,
                Verb::DeleteRecursive,
                Verb::Move,
                Verb::Copy,
                Verb::Share,
                Verb::Upload,
                Verb::Download,
                Verb::Export,
                Verb::Search,
            ],
            Self::Db => &[
                Verb::Select,
                Verb::Insert,
                Verb::Update,
                Verb::Delete,
                Verb::Create,
                Verb::Alter,
                Verb::Drop,
                Verb::Truncate,
                Verb::GrantAccess,
                Verb::RevokeAccess,
                Verb::Export,
                Verb::Backup,
                Verb::Restore,
            ],
            Self::Crm => &[
                Verb::List,
                Verb::Get,
                Verb::Search,
                Verb::Create,
                Verb::Update,
                Verb::Delete,
                Verb::LogActivity,
                Verb::Export,
            ],
            Self::Payment => &[
                Verb::Charge,
                Verb::Refund,
                Verb::Transfer,
                Verb::GetBalance,
                Verb::List,
                Verb::Get,
                Verb::Create,
                Verb::Update,
                Verb::CancelSubscription,
            ],
            Self::Legal => &[Verb::SignDocument, Verb::SubmitFiling, Verb::AcceptTerms],
            Self::Iam => &[
                Verb::List,
                Verb::Get,
                Verb::Create,
                Verb::Update,
                Verb::Delete,
                Verb::AssignRole,
                Verb::RevokeRole,
                Verb::ResetPassword,
                Verb::GenerateApiKey,
                Verb::RevokeApiKey,
            ],
            Self::Secret => &[
                Verb::Get,
                Verb::List,
                Verb::Create,
                Verb::Update,
                Verb::Rotate,
                Verb::Delete,
            ],
            Self::Infra => &[
                Verb::List,
                Verb::Get,
                Verb::Create,
                Verb::Update,
                Verb::Terminate,
                Verb::Scale,
            ],
            Self::Process => &[Verb::Run, Verb::Invoke],
            Self::Network => &[
                Verb::Get,
                Verb::Post,
                Verb::Put,
                Verb::Delete,
                Verb::SendWebhook,
            ],
            Self::Dev => &[
                Verb::List,
                Verb::Get,
                Verb::Create,
                Verb::Update,
                Verb::CloseIssue,
                Verb::MergePr,
                Verb::PushCode,
                Verb::Deploy,
                Verb::RunPipeline,
            ],
            Self::Browser => &[
                Verb::Navigate,
                Verb::Click,
                Verb::FillForm,
                Verb::SubmitForm,
                Verb::TakeScreenshot,
                Verb::DownloadFile,
                Verb::ExecuteJs,
                Verb::Scrape,
            ],
            Self::Device => &[
                Verb::Lock,
                Verb::Unlock,
                Verb::Enable,
                Verb::Disable,
                Verb::Move,
            ],
            Self::Ai => &[
                Verb::Prompt,
                Verb::Embed,
                Verb::FineTune,
                Verb::InvokeAgent,
                Verb::GenerateImage,
            ],
            Self::Unknown => &[Verb::Unclassified],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Message => "message",
            Self::Social => "social",
            Self::Cms => "cms",
            Self::Newsletter => "newsletter",
            Self::Calendar => "calendar",
            Self::Task => "task",
            Self::File => "file",
            Self::Db => "db",
            Self::Crm => "crm",
            Self::Payment => "payment",
            Self::Legal => "legal",
            Self::Iam => "iam",
            Self::Secret => "secret",
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

/// Verbs in the action taxonomy.
///
/// Generic verbs (`Get`, `List`, `Create`, `Update`, `Delete`, `Search`,
/// `Move`, `Copy`, `Export`, `Send`, `Post`, `Schedule`, `Draft`) are
/// reused across domains. Specific verbs are added when the risk profile
/// of the operation differs sharply from the generic one (`SetForwarding`
/// in email is account takeover; `Charge` in payment is value transfer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    // ── Generic CRUD + read (shared across many domains) ──
    Get,
    List,
    Read,
    Create,
    Update,
    Delete,
    Search,
    Export,

    // ── Email-specific ──
    ReadThread,
    ListMailboxes,
    Draft,
    ListDrafts,
    Send,
    MarkRead,
    Flag,
    Move,
    Archive,
    MarkSpam,
    CreateMailbox,
    SetForwarding,
    AddDelegate,

    // ── Message ──
    PostChannel,
    SendDm,
    SendSms,
    React,

    // ── Social ──
    Post,
    Reply,
    Like,

    // ── CMS ──
    Publish,
    Unpublish,
    Schedule,

    // ── Newsletter ──
    Unsubscribe,

    // ── Calendar ──
    Rsvp,

    // ── Task ──
    Complete,
    Assign,
    Comment,

    // ── File ──
    DeleteRecursive,
    Copy,
    Share,
    Upload,
    Download,

    // ── Db ──
    Select,
    Insert,
    Alter,
    Drop,
    Truncate,
    GrantAccess,
    RevokeAccess,
    Backup,
    Restore,

    // ── Crm ──
    LogActivity,

    // ── Payment ──
    Charge,
    Refund,
    Transfer,
    GetBalance,
    CancelSubscription,

    // ── Legal ──
    SignDocument,
    SubmitFiling,
    AcceptTerms,

    // ── Iam ──
    AssignRole,
    RevokeRole,
    ResetPassword,
    GenerateApiKey,
    RevokeApiKey,

    // ── Secret ──
    Rotate,

    // ── Infra ──
    Terminate,
    Scale,

    // ── Process ──
    Run,
    Invoke,

    // ── Network ──
    Put,
    SendWebhook,

    // ── Dev ──
    CloseIssue,
    MergePr,
    PushCode,
    Deploy,
    RunPipeline,

    // ── Browser ──
    Navigate,
    Click,
    FillForm,
    SubmitForm,
    TakeScreenshot,
    DownloadFile,
    ExecuteJs,
    Scrape,

    // ── Device ──
    Lock,
    Unlock,
    Enable,
    Disable,

    // ── Ai ──
    Prompt,
    Embed,
    FineTune,
    InvokeAgent,
    GenerateImage,

    // ── Unknown ──
    Unclassified,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::List => "list",
            Self::Read => "read",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Search => "search",
            Self::Export => "export",
            Self::ReadThread => "read_thread",
            Self::ListMailboxes => "list_mailboxes",
            Self::Draft => "draft",
            Self::ListDrafts => "list_drafts",
            Self::Send => "send",
            Self::MarkRead => "mark_read",
            Self::Flag => "flag",
            Self::Move => "move",
            Self::Archive => "archive",
            Self::MarkSpam => "mark_spam",
            Self::CreateMailbox => "create_mailbox",
            Self::SetForwarding => "set_forwarding",
            Self::AddDelegate => "add_delegate",
            Self::PostChannel => "post_channel",
            Self::SendDm => "send_dm",
            Self::SendSms => "send_sms",
            Self::React => "react",
            Self::Post => "post",
            Self::Reply => "reply",
            Self::Like => "like",
            Self::Publish => "publish",
            Self::Unpublish => "unpublish",
            Self::Schedule => "schedule",
            Self::Unsubscribe => "unsubscribe",
            Self::Rsvp => "rsvp",
            Self::Complete => "complete",
            Self::Assign => "assign",
            Self::Comment => "comment",
            Self::DeleteRecursive => "delete_recursive",
            Self::Copy => "copy",
            Self::Share => "share",
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Alter => "alter",
            Self::Drop => "drop",
            Self::Truncate => "truncate",
            Self::GrantAccess => "grant_access",
            Self::RevokeAccess => "revoke_access",
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::LogActivity => "log_activity",
            Self::Charge => "charge",
            Self::Refund => "refund",
            Self::Transfer => "transfer",
            Self::GetBalance => "get_balance",
            Self::CancelSubscription => "cancel_subscription",
            Self::SignDocument => "sign_document",
            Self::SubmitFiling => "submit_filing",
            Self::AcceptTerms => "accept_terms",
            Self::AssignRole => "assign_role",
            Self::RevokeRole => "revoke_role",
            Self::ResetPassword => "reset_password",
            Self::GenerateApiKey => "generate_api_key",
            Self::RevokeApiKey => "revoke_api_key",
            Self::Rotate => "rotate",
            Self::Terminate => "terminate",
            Self::Scale => "scale",
            Self::Run => "run",
            Self::Invoke => "invoke",
            Self::Put => "put",
            Self::SendWebhook => "send_webhook",
            Self::CloseIssue => "close_issue",
            Self::MergePr => "merge_pr",
            Self::PushCode => "push_code",
            Self::Deploy => "deploy",
            Self::RunPipeline => "run_pipeline",
            Self::Navigate => "navigate",
            Self::Click => "click",
            Self::FillForm => "fill_form",
            Self::SubmitForm => "submit_form",
            Self::TakeScreenshot => "take_screenshot",
            Self::DownloadFile => "download_file",
            Self::ExecuteJs => "execute_js",
            Self::Scrape => "scrape",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Prompt => "prompt",
            Self::Embed => "embed",
            Self::FineTune => "fine_tune",
            Self::InvokeAgent => "invoke_agent",
            Self::GenerateImage => "generate_image",
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

/// A validated `domain.verb` pair from the action taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionType {
    pub domain: Domain,
    pub verb: Verb,
}

impl ActionType {
    /// Create a new ActionType, validating that the verb belongs to the domain.
    pub fn new(domain: Domain, verb: Verb) -> Result<Self, TaxonomyError> {
        if domain.verbs().contains(&verb) {
            Ok(Self { domain, verb })
        } else {
            Err(TaxonomyError::InvalidCombination { domain, verb })
        }
    }

    /// The `domain.verb` string form (e.g. "payment.charge").
    pub fn as_action_str(&self) -> String {
        format!("{}.{}", self.domain, self.verb)
    }

    /// Parse from a `domain.verb` string (e.g. "payment.charge").
    pub fn parse(s: &str) -> Result<Self, TaxonomyError> {
        let (domain_str, verb_str) = s.split_once('.').ok_or_else(|| {
            TaxonomyError::ParseError(format!("expected 'domain.verb', got '{s}'"))
        })?;
        let domain = Domain::parse(domain_str)
            .ok_or_else(|| TaxonomyError::UnknownDomain(domain_str.to_string()))?;
        let verb =
            Verb::parse(verb_str).ok_or_else(|| TaxonomyError::UnknownVerb(verb_str.to_string()))?;
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
pub enum TaxonomyError {
    #[error("invalid combination: verb '{verb}' is not valid for domain '{domain}'")]
    InvalidCombination { domain: Domain, verb: Verb },
    #[error("unknown domain: '{0}'")]
    UnknownDomain(String),
    #[error("unknown verb: '{0}'")]
    UnknownVerb(String),
    #[error("parse error: {0}")]
    ParseError(String),
}

/// All domains in the taxonomy.
pub const ALL_DOMAINS: &[Domain] = &[
    Domain::Email,
    Domain::Message,
    Domain::Social,
    Domain::Cms,
    Domain::Newsletter,
    Domain::Calendar,
    Domain::Task,
    Domain::File,
    Domain::Db,
    Domain::Crm,
    Domain::Payment,
    Domain::Legal,
    Domain::Iam,
    Domain::Secret,
    Domain::Infra,
    Domain::Process,
    Domain::Network,
    Domain::Dev,
    Domain::Browser,
    Domain::Device,
    Domain::Ai,
    Domain::Unknown,
];

/// All verbs in the taxonomy (flat list, deduplicated).
const ALL_VERBS: &[Verb] = &[
    // Generic CRUD + read
    Verb::Get,
    Verb::List,
    Verb::Read,
    Verb::Create,
    Verb::Update,
    Verb::Delete,
    Verb::Search,
    Verb::Export,
    // Email
    Verb::ReadThread,
    Verb::ListMailboxes,
    Verb::Draft,
    Verb::ListDrafts,
    Verb::Send,
    Verb::MarkRead,
    Verb::Flag,
    Verb::Move,
    Verb::Archive,
    Verb::MarkSpam,
    Verb::CreateMailbox,
    Verb::SetForwarding,
    Verb::AddDelegate,
    // Message
    Verb::PostChannel,
    Verb::SendDm,
    Verb::SendSms,
    Verb::React,
    // Social
    Verb::Post,
    Verb::Reply,
    Verb::Like,
    // CMS
    Verb::Publish,
    Verb::Unpublish,
    Verb::Schedule,
    // Newsletter
    Verb::Unsubscribe,
    // Calendar
    Verb::Rsvp,
    // Task
    Verb::Complete,
    Verb::Assign,
    Verb::Comment,
    // File
    Verb::DeleteRecursive,
    Verb::Copy,
    Verb::Share,
    Verb::Upload,
    Verb::Download,
    // Db
    Verb::Select,
    Verb::Insert,
    Verb::Alter,
    Verb::Drop,
    Verb::Truncate,
    Verb::GrantAccess,
    Verb::RevokeAccess,
    Verb::Backup,
    Verb::Restore,
    // Crm
    Verb::LogActivity,
    // Payment
    Verb::Charge,
    Verb::Refund,
    Verb::Transfer,
    Verb::GetBalance,
    Verb::CancelSubscription,
    // Legal
    Verb::SignDocument,
    Verb::SubmitFiling,
    Verb::AcceptTerms,
    // Iam
    Verb::AssignRole,
    Verb::RevokeRole,
    Verb::ResetPassword,
    Verb::GenerateApiKey,
    Verb::RevokeApiKey,
    // Secret
    Verb::Rotate,
    // Infra
    Verb::Terminate,
    Verb::Scale,
    // Process
    Verb::Run,
    Verb::Invoke,
    // Network
    Verb::Put,
    Verb::SendWebhook,
    // Dev
    Verb::CloseIssue,
    Verb::MergePr,
    Verb::PushCode,
    Verb::Deploy,
    Verb::RunPipeline,
    // Browser
    Verb::Navigate,
    Verb::Click,
    Verb::FillForm,
    Verb::SubmitForm,
    Verb::TakeScreenshot,
    Verb::DownloadFile,
    Verb::ExecuteJs,
    Verb::Scrape,
    // Device
    Verb::Lock,
    Verb::Unlock,
    Verb::Enable,
    Verb::Disable,
    // Ai
    Verb::Prompt,
    Verb::Embed,
    Verb::FineTune,
    Verb::InvokeAgent,
    Verb::GenerateImage,
    // Unknown
    Verb::Unclassified,
];

/// All valid `ActionType` entries in the taxonomy.
pub fn all_action_types() -> Vec<ActionType> {
    ALL_DOMAINS
        .iter()
        .flat_map(|d| {
            d.verbs().iter().map(move |v| ActionType {
                domain: *d,
                verb: *v,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_action_type() {
        let at = ActionType::parse("payment.charge").unwrap();
        assert_eq!(at.domain, Domain::Payment);
        assert_eq!(at.verb, Verb::Charge);
        assert_eq!(at.as_action_str(), "payment.charge");
    }

    #[test]
    fn email_full_set_intact() {
        // Detailed email taxonomy preserved (16 verbs).
        assert_eq!(Domain::Email.verbs().len(), 16);
        assert!(ActionType::parse("email.send").is_ok());
        assert!(ActionType::parse("email.read_thread").is_ok());
        assert!(ActionType::parse("email.set_forwarding").is_ok());
        assert!(ActionType::parse("email.list_drafts").is_ok());
    }

    #[test]
    fn parse_invalid_combination() {
        let err = ActionType::parse("email.charge");
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            TaxonomyError::InvalidCombination { .. }
        ));
    }

    #[test]
    fn parse_unknown_domain() {
        let err = ActionType::parse("foobar.send");
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), TaxonomyError::UnknownDomain(_)));
    }

    #[test]
    fn parse_unknown_verb() {
        let err = ActionType::parse("email.explode");
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), TaxonomyError::UnknownVerb(_)));
    }

    #[test]
    fn parse_no_dot() {
        let err = ActionType::parse("nodot");
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), TaxonomyError::ParseError(_)));
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
        let expected = ALL_DOMAINS.iter().map(|d| d.verbs().len()).sum::<usize>();
        assert_eq!(all.len(), expected);
        assert!(
            all.len() > 100,
            "taxonomy should have >100 entries, got {}",
            all.len()
        );
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

    #[test]
    fn generic_verbs_reused_across_domains() {
        // `get` should be valid in many domains (not just one)
        let domains_with_get: Vec<_> = ALL_DOMAINS
            .iter()
            .filter(|d| d.verbs().contains(&Verb::Get))
            .collect();
        assert!(
            domains_with_get.len() >= 5,
            "expected `get` to be reused across many domains, got {}",
            domains_with_get.len()
        );
    }
}
