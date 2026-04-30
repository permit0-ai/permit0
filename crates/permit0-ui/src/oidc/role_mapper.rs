#![forbid(unsafe_code)]

use std::collections::HashMap;

use super::config::UserInfo;
use crate::auth::Role;

/// Maps OIDC claims (email, groups) to a permit0 Role.
///
/// Mapping rules:
/// 1. Check if user's email or any group matches an admin mapping → Admin
/// 2. Check if user's email or any group matches an approver mapping → Approver
/// 3. Default → Viewer
///
/// The highest matching role wins (Admin > Approver > Viewer).
pub struct RoleMapper {
    /// Map of role name → set of emails/groups that grant that role.
    mapping: HashMap<String, Vec<String>>,
    /// Allowed email domains (empty = allow all).
    allowed_domains: Vec<String>,
}

impl RoleMapper {
    pub fn new(mapping: HashMap<String, Vec<String>>, allowed_domains: Vec<String>) -> Self {
        Self {
            mapping,
            allowed_domains,
        }
    }

    /// Check if a user's email domain is allowed.
    pub fn is_domain_allowed(&self, email: &str) -> bool {
        if self.allowed_domains.is_empty() {
            return true;
        }
        let domain = email.rsplit('@').next().unwrap_or("");
        self.allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
    }

    /// Resolve the user's role from their OIDC claims.
    pub fn resolve_role(&self, user_info: &UserInfo) -> Role {
        let identifiers: Vec<&str> = user_info
            .groups
            .iter()
            .map(String::as_str)
            .chain(user_info.email.as_deref())
            .collect();

        // Check admin first (highest privilege)
        if self.matches_role("admin", &identifiers) {
            return Role::Admin;
        }
        if self.matches_role("approver", &identifiers) {
            return Role::Approver;
        }
        Role::Viewer
    }

    fn matches_role(&self, role_name: &str, identifiers: &[&str]) -> bool {
        if let Some(mappings) = self.mapping.get(role_name) {
            for mapping in mappings {
                for id in identifiers {
                    if mapping.eq_ignore_ascii_case(id) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mapper() -> RoleMapper {
        RoleMapper::new(
            HashMap::from([
                (
                    "admin".into(),
                    vec!["security-team@acme.com".into(), "admin@acme.com".into()],
                ),
                ("approver".into(), vec!["engineering@acme.com".into()]),
            ]),
            vec!["acme.com".into()],
        )
    }

    fn user_info(email: &str, groups: Vec<&str>) -> UserInfo {
        UserInfo {
            sub: "user-1".into(),
            email: Some(email.into()),
            name: Some("Test User".into()),
            groups: groups.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn admin_via_group() {
        let mapper = test_mapper();
        let info = user_info("alice@acme.com", vec!["security-team@acme.com"]);
        assert_eq!(mapper.resolve_role(&info), Role::Admin);
    }

    #[test]
    fn admin_via_email() {
        let mapper = test_mapper();
        let info = user_info("admin@acme.com", vec![]);
        assert_eq!(mapper.resolve_role(&info), Role::Admin);
    }

    #[test]
    fn approver_via_group() {
        let mapper = test_mapper();
        let info = user_info("bob@acme.com", vec!["engineering@acme.com"]);
        assert_eq!(mapper.resolve_role(&info), Role::Approver);
    }

    #[test]
    fn default_viewer() {
        let mapper = test_mapper();
        let info = user_info("eve@acme.com", vec![]);
        assert_eq!(mapper.resolve_role(&info), Role::Viewer);
    }

    #[test]
    fn admin_wins_over_approver() {
        let mapper = test_mapper();
        let info = user_info(
            "alice@acme.com",
            vec!["security-team@acme.com", "engineering@acme.com"],
        );
        assert_eq!(mapper.resolve_role(&info), Role::Admin);
    }

    #[test]
    fn domain_allowed() {
        let mapper = test_mapper();
        assert!(mapper.is_domain_allowed("alice@acme.com"));
        assert!(!mapper.is_domain_allowed("alice@evil.com"));
    }

    #[test]
    fn empty_domain_list_allows_all() {
        let mapper = RoleMapper::new(HashMap::new(), vec![]);
        assert!(mapper.is_domain_allowed("anyone@anywhere.com"));
    }

    #[test]
    fn case_insensitive_matching() {
        let mapper = test_mapper();
        let info = user_info("ADMIN@ACME.COM", vec![]);
        assert_eq!(mapper.resolve_role(&info), Role::Admin);
    }
}
