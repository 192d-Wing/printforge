// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IdP` group to `PrintForge` role mapping with wildcard support.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! Fleet administrators configure mapping rules that translate `IdP` group
//! names (from OIDC/SAML claims) into `PrintForge` roles. Wildcards are
//! supported for site-scoped roles (e.g., `PrintForge-SiteAdmin-*` maps
//! to `SiteAdmin(extracted_site)`).

use pf_common::identity::{Role, SiteId};
use serde::{Deserialize, Serialize};

/// A single rule mapping an `IdP` group pattern to a `PrintForge` role.
///
/// Patterns support a trailing `*` wildcard. When the wildcard matches,
/// the captured suffix is used as the site identifier for site-scoped roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMappingRule {
    /// The `IdP` group pattern (e.g., `"PrintForge-SiteAdmin-*"`).
    pub group_pattern: String,
    /// The `PrintForge` role to assign (e.g., `"SiteAdmin"`, `"FleetAdmin"`, `"Auditor"`, `"User"`).
    pub target_role: String,
}

/// Result of evaluating role mapping rules against a user's `IdP` groups.
#[derive(Debug, Clone)]
pub struct RoleMappingResult {
    /// The roles assigned based on matching rules.
    pub roles: Vec<Role>,
    /// Groups that matched at least one rule.
    pub matched_groups: Vec<String>,
    /// Groups that did not match any rule.
    pub unmatched_groups: Vec<String>,
}

/// Evaluate a set of role mapping rules against the user's `IdP` groups.
///
/// Returns the set of `PrintForge` roles derived from matching rules.
/// If no rules match, the caller should apply the default role.
///
/// # Arguments
///
/// * `rules` - The configured role mapping rules.
/// * `groups` - The `IdP` group names from the user's claims.
/// * `max_groups` - Maximum number of groups to evaluate (denial-of-service protection).
#[must_use]
pub fn evaluate_role_mappings(
    rules: &[RoleMappingRule],
    groups: &[String],
    max_groups: usize,
) -> RoleMappingResult {
    let mut assigned_roles = Vec::new();
    let mut matched_groups = Vec::new();
    let mut unmatched_groups = Vec::new();

    // Limit the number of groups evaluated to prevent DoS.
    let capped_groups = if groups.len() > max_groups {
        tracing::warn!(
            total_groups = groups.len(),
            max_groups,
            "truncating group list to max_groups limit"
        );
        &groups[..max_groups]
    } else {
        groups
    };

    for group in capped_groups {
        let mut matched = false;
        for rule in rules {
            if let Some(role) = match_rule(rule, group) {
                // Deduplicate roles.
                if !assigned_roles.contains(&role) {
                    assigned_roles.push(role);
                }
                matched = true;
            }
        }
        if matched {
            matched_groups.push(group.clone());
        } else {
            unmatched_groups.push(group.clone());
        }
    }

    RoleMappingResult {
        roles: assigned_roles,
        matched_groups,
        unmatched_groups,
    }
}

/// Parse a target role string into a `PrintForge` [`Role`].
///
/// For `SiteAdmin`, the site identifier must be provided separately
/// (extracted from the wildcard match).
fn parse_role(target_role: &str, site_id: Option<&str>) -> Option<Role> {
    match target_role {
        "User" => Some(Role::User),
        "FleetAdmin" => Some(Role::FleetAdmin),
        "Auditor" => Some(Role::Auditor),
        "SiteAdmin" => {
            let site = site_id.unwrap_or("unknown");
            Some(Role::SiteAdmin(SiteId(site.to_string())))
        }
        _ => {
            tracing::warn!(target_role, "unknown target role in mapping rule");
            None
        }
    }
}

/// Check whether an `IdP` group matches a mapping rule pattern.
///
/// Supports exact match and trailing wildcard (`*`). When a wildcard
/// matches, the suffix is used as the site identifier.
fn match_rule(rule: &RoleMappingRule, group: &str) -> Option<Role> {
    if let Some(prefix) = rule.group_pattern.strip_suffix('*') {
        // Wildcard match: extract the suffix after the prefix.
        if let Some(suffix) = group.strip_prefix(prefix) {
            if suffix.is_empty() {
                // Wildcard matched but no suffix — treat as exact prefix match.
                return parse_role(&rule.target_role, None);
            }
            return parse_role(&rule.target_role, Some(suffix));
        }
    } else if rule.group_pattern == group {
        // Exact match.
        return parse_role(&rule.target_role, None);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules() -> Vec<RoleMappingRule> {
        vec![
            RoleMappingRule {
                group_pattern: "PrintForge-Users".to_string(),
                target_role: "User".to_string(),
            },
            RoleMappingRule {
                group_pattern: "PrintForge-SiteAdmin-*".to_string(),
                target_role: "SiteAdmin".to_string(),
            },
            RoleMappingRule {
                group_pattern: "PrintForge-FleetAdmin".to_string(),
                target_role: "FleetAdmin".to_string(),
            },
            RoleMappingRule {
                group_pattern: "PrintForge-Auditor".to_string(),
                target_role: "Auditor".to_string(),
            },
        ]
    }

    #[test]
    fn exact_match_user_role() {
        let rules = test_rules();
        let groups = vec!["PrintForge-Users".to_string()];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert_eq!(result.roles, vec![Role::User]);
        assert_eq!(result.matched_groups.len(), 1);
        assert!(result.unmatched_groups.is_empty());
    }

    #[test]
    fn wildcard_match_site_admin() {
        let rules = test_rules();
        let groups = vec!["PrintForge-SiteAdmin-Maxwell".to_string()];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert_eq!(result.roles.len(), 1);
        assert_eq!(
            result.roles[0],
            Role::SiteAdmin(SiteId("Maxwell".to_string()))
        );
    }

    #[test]
    fn multiple_groups_multiple_roles() {
        let rules = test_rules();
        let groups = vec![
            "PrintForge-Users".to_string(),
            "PrintForge-SiteAdmin-Langley".to_string(),
        ];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert_eq!(result.roles.len(), 2);
        assert!(result.roles.contains(&Role::User));
        assert!(
            result
                .roles
                .contains(&Role::SiteAdmin(SiteId("Langley".to_string())))
        );
    }

    #[test]
    fn no_matching_groups() {
        let rules = test_rules();
        let groups = vec!["SomeOtherGroup".to_string()];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert!(result.roles.is_empty());
        assert!(result.matched_groups.is_empty());
        assert_eq!(result.unmatched_groups, vec!["SomeOtherGroup"]);
    }

    #[test]
    fn empty_groups() {
        let rules = test_rules();
        let result = evaluate_role_mappings(&rules, &[], 100);
        assert!(result.roles.is_empty());
    }

    #[test]
    fn max_groups_limits_evaluation() {
        let rules = test_rules();
        let groups: Vec<String> = (0..200).map(|i| format!("Group-{i}")).collect();
        let result = evaluate_role_mappings(&rules, &groups, 50);
        // Only first 50 groups are evaluated.
        assert_eq!(
            result.unmatched_groups.len() + result.matched_groups.len(),
            50
        );
    }

    #[test]
    fn duplicate_roles_are_deduplicated() {
        let rules = vec![
            RoleMappingRule {
                group_pattern: "GroupA".to_string(),
                target_role: "User".to_string(),
            },
            RoleMappingRule {
                group_pattern: "GroupB".to_string(),
                target_role: "User".to_string(),
            },
        ];
        let groups = vec!["GroupA".to_string(), "GroupB".to_string()];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert_eq!(result.roles.len(), 1);
        assert_eq!(result.roles[0], Role::User);
    }

    #[test]
    fn multiple_site_admin_sites() {
        let rules = test_rules();
        let groups = vec![
            "PrintForge-SiteAdmin-Maxwell".to_string(),
            "PrintForge-SiteAdmin-Langley".to_string(),
        ];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert_eq!(result.roles.len(), 2);
    }

    #[test]
    fn nist_ac2_role_assignment_from_idp_groups() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Roles are assigned based on IdP group membership mappings.
        let rules = test_rules();
        let groups = vec![
            "PrintForge-Users".to_string(),
            "PrintForge-FleetAdmin".to_string(),
        ];
        let result = evaluate_role_mappings(&rules, &groups, 100);
        assert!(result.roles.contains(&Role::User));
        assert!(result.roles.contains(&Role::FleetAdmin));
    }
}
