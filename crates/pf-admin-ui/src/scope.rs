// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Data scoping enforcement for the admin dashboard.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
//!
//! Every query MUST be scoped by the requester's role and site assignment.
//! A `SiteAdmin` for one installation MUST NOT see data from another.

use pf_common::identity::{Role, SiteId};

use crate::error::AdminUiError;

/// Describes the data scope visible to the current requester.
///
/// Built from the requester's [`Role`] list and used to filter every
/// database query.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[derive(Debug, Clone)]
pub enum DataScope {
    /// Full visibility across all sites (Fleet Admin, Auditor).
    Global,
    /// Visibility restricted to the listed sites (Site Admin).
    Sites(Vec<SiteId>),
}

/// Derive the [`DataScope`] for a set of roles.
///
/// Fleet Admins and Auditors get [`DataScope::Global`]. Site Admins get
/// visibility only to their assigned sites. Users without an admin role
/// are denied access entirely.
///
/// # Errors
///
/// Returns [`AdminUiError::AccessDenied`] if none of the roles grant
/// admin dashboard access.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
pub fn derive_scope(roles: &[Role]) -> Result<DataScope, AdminUiError> {
    let mut sites: Vec<SiteId> = Vec::new();

    for role in roles {
        match role {
            Role::FleetAdmin | Role::Auditor => return Ok(DataScope::Global),
            Role::SiteAdmin(site_id) => sites.push(site_id.clone()),
            Role::User => {}
        }
    }

    if sites.is_empty() {
        return Err(AdminUiError::AccessDenied);
    }

    Ok(DataScope::Sites(sites))
}

/// Convert a [`DataScope`] into the list of installation names used by the
/// fleet/jobs repositories to filter rows.
///
/// Returns an empty vector for [`DataScope::Global`] (meaning "no site
/// filter"). For [`DataScope::Sites`], returns the inner installation
/// strings.
///
/// Callers feed the result into `PrinterQuery::installations` (or the
/// equivalent field on other services). An empty vector means unfiltered
/// in the repo layer.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[must_use]
pub fn scope_to_installations(scope: &DataScope) -> Vec<String> {
    match scope {
        DataScope::Global => Vec::new(),
        DataScope::Sites(sites) => sites.iter().map(|s| s.0.clone()).collect(),
    }
}

/// Check that a specific site is visible under the given scope.
///
/// # Errors
///
/// Returns [`AdminUiError::ScopeViolation`] if the site is not within the
/// requester's data scope.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
pub fn require_site_access(scope: &DataScope, site: &SiteId) -> Result<(), AdminUiError> {
    match scope {
        DataScope::Global => Ok(()),
        DataScope::Sites(allowed) => {
            if allowed.iter().any(|s| s == site) {
                Ok(())
            } else {
                Err(AdminUiError::ScopeViolation)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(name: &str) -> SiteId {
        SiteId(name.to_string())
    }

    #[test]
    fn nist_ac3_fleet_admin_gets_global_scope() {
        let roles = vec![Role::FleetAdmin];
        let scope = derive_scope(&roles).unwrap();
        assert!(matches!(scope, DataScope::Global));
    }

    #[test]
    fn nist_ac3_auditor_gets_global_scope() {
        let roles = vec![Role::Auditor];
        let scope = derive_scope(&roles).unwrap();
        assert!(matches!(scope, DataScope::Global));
    }

    #[test]
    fn nist_ac3_site_admin_scoped_to_own_sites() {
        let roles = vec![
            Role::SiteAdmin(site("langley")),
            Role::SiteAdmin(site("ramstein")),
        ];
        let scope = derive_scope(&roles).unwrap();
        match scope {
            DataScope::Sites(sites) => {
                assert_eq!(sites.len(), 2);
            }
            DataScope::Global => panic!("expected Sites scope"),
        }
    }

    #[test]
    fn nist_ac3_plain_user_denied_dashboard_access() {
        let roles = vec![Role::User];
        let result = derive_scope(&roles);
        assert!(result.is_err());
    }

    #[test]
    fn nist_ac3_site_admin_cannot_see_other_site() {
        let scope = DataScope::Sites(vec![site("langley")]);
        let result = require_site_access(&scope, &site("ramstein"));
        assert!(result.is_err());
    }

    #[test]
    fn nist_ac3_site_admin_can_see_own_site() {
        let scope = DataScope::Sites(vec![site("langley")]);
        let result = require_site_access(&scope, &site("langley"));
        assert!(result.is_ok());
    }

    #[test]
    fn nist_ac3_global_scope_can_see_any_site() {
        let scope = DataScope::Global;
        let result = require_site_access(&scope, &site("anywhere"));
        assert!(result.is_ok());
    }

    #[test]
    fn nist_ac3_scope_to_installations_global_is_empty() {
        // Global scope applies no installation filter — repositories treat
        // an empty `installations` list as "no constraint".
        let scope = DataScope::Global;
        assert!(scope_to_installations(&scope).is_empty());
    }

    #[test]
    fn nist_ac3_scope_to_installations_passes_site_names() {
        let scope = DataScope::Sites(vec![site("langley"), site("ramstein")]);
        let installations = scope_to_installations(&scope);
        assert_eq!(installations, vec!["langley".to_string(), "ramstein".to_string()]);
    }

    #[test]
    fn nist_ac3_mixed_roles_fleet_admin_wins() {
        let roles = vec![Role::SiteAdmin(site("langley")), Role::FleetAdmin];
        let scope = derive_scope(&roles).unwrap();
        assert!(matches!(scope, DataScope::Global));
    }

    #[test]
    fn nist_ac3_empty_roles_denied() {
        let result = derive_scope(&[]);
        assert!(result.is_err());
    }
}
