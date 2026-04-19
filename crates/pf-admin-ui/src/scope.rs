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

/// Check that a mutation against a target row with the given `site_id` is
/// authorized under the caller's scope.
///
/// Unlike [`require_site_access`], this variant takes the raw site string
/// and **fails closed on empty**: an unattributed row (`site_id = ""`) is
/// not reachable by any non-Global caller. This closes a bypass where a
/// `SiteAdmin` could modify users / rows that had not yet been assigned a
/// site (pre-migration data, `SCIM`-provisioned rows before first login,
/// or `JIT` rows whose `OIDC` claim lacked `site`).
///
/// # Errors
///
/// Returns [`AdminUiError::ScopeViolation`] if the target is outside the
/// caller's scope OR unattributed and the caller is not Global.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
pub fn require_target_site_access(
    scope: &DataScope,
    site_id: &str,
) -> Result<(), AdminUiError> {
    match scope {
        DataScope::Global => Ok(()),
        DataScope::Sites(allowed) => {
            if site_id.is_empty() {
                return Err(AdminUiError::ScopeViolation);
            }
            if allowed.iter().any(|s| s.0 == site_id) {
                Ok(())
            } else {
                Err(AdminUiError::ScopeViolation)
            }
        }
    }
}

/// Require that an Option-typed site filter is either present and in the
/// caller's scope, or absent only when the caller is Global.
///
/// Used at endpoints that accept `site_id: Option<SiteId>` as a filter.
/// A site-scoped caller passing `None` would otherwise mean "no filter"
/// (fleet-wide), which is a privilege escalation. This helper forces
/// site-scoped callers to specify a site they're authorized for.
///
/// # Errors
///
/// Returns [`AdminUiError::ScopeViolation`] if the caller is site-scoped
/// and the filter is `None`, or if the supplied site is outside scope.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
pub fn require_site_filter(
    scope: &DataScope,
    site_id: Option<&SiteId>,
) -> Result<(), AdminUiError> {
    match scope {
        DataScope::Global => Ok(()),
        DataScope::Sites(_) => match site_id {
            Some(site) => require_site_access(scope, site),
            None => Err(AdminUiError::ScopeViolation),
        },
    }
}

/// Check whether the caller's role set permits granting `role_to_grant`
/// to another user.
///
/// Rules:
/// - `FleetAdmin` may grant any role (including `FleetAdmin` or `Auditor`).
/// - `SiteAdmin(X)` may grant `User` or `SiteAdmin(X)` only — never
///   `FleetAdmin`, `Auditor`, or a `SiteAdmin` at a different site.
/// - Anyone else (including `Auditor` alone) may not grant any role.
///   `Auditor` is read-only per the role model — letting it mutate role
///   assignments would defeat the separation of duties that Auditor
///   exists to enforce.
///
/// # Errors
///
/// Returns [`AdminUiError::AccessDenied`] when the caller cannot grant
/// the requested role.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, AC-6 — Least
/// Privilege.
pub fn require_can_grant_role(
    caller_roles: &[Role],
    role_to_grant: &Role,
) -> Result<(), AdminUiError> {
    if caller_roles.iter().any(|r| matches!(r, Role::FleetAdmin)) {
        return Ok(());
    }

    match role_to_grant {
        Role::User => {
            if caller_roles.iter().any(|r| matches!(r, Role::SiteAdmin(_))) {
                Ok(())
            } else {
                Err(AdminUiError::AccessDenied)
            }
        }
        Role::SiteAdmin(target_site) => {
            let ok = caller_roles
                .iter()
                .any(|r| matches!(r, Role::SiteAdmin(s) if s == target_site));
            if ok {
                Ok(())
            } else {
                Err(AdminUiError::AccessDenied)
            }
        }
        Role::FleetAdmin | Role::Auditor => Err(AdminUiError::AccessDenied),
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

    // ── require_target_site_access (fail-closed on empty site_id) ────

    #[test]
    fn nist_ac3_target_site_access_global_allows_empty() {
        // Global scope is the one case where an unattributed row is
        // still reachable — Fleet Admins may touch anything, including
        // pre-migration / SCIM-unattributed rows.
        let scope = DataScope::Global;
        assert!(require_target_site_access(&scope, "").is_ok());
        assert!(require_target_site_access(&scope, "anywhere").is_ok());
    }

    #[test]
    fn nist_ac3_target_site_access_site_scope_rejects_empty() {
        // Evidence against the "empty site_id bypass" class of vuln:
        // a SiteAdmin cannot touch an unattributed row.
        let scope = DataScope::Sites(vec![site("langley")]);
        let result = require_target_site_access(&scope, "");
        assert!(matches!(result, Err(AdminUiError::ScopeViolation)));
    }

    #[test]
    fn nist_ac3_target_site_access_site_scope_rejects_other_site() {
        let scope = DataScope::Sites(vec![site("langley")]);
        let result = require_target_site_access(&scope, "ramstein");
        assert!(matches!(result, Err(AdminUiError::ScopeViolation)));
    }

    #[test]
    fn nist_ac3_target_site_access_site_scope_allows_own_site() {
        let scope = DataScope::Sites(vec![site("langley")]);
        assert!(require_target_site_access(&scope, "langley").is_ok());
    }

    // ── require_site_filter (reject None for site-scoped callers) ────

    #[test]
    fn nist_ac3_site_filter_global_allows_none() {
        // Fleet Admin may omit site_id to request fleet-wide data.
        let scope = DataScope::Global;
        assert!(require_site_filter(&scope, None).is_ok());
    }

    #[test]
    fn nist_ac3_site_filter_site_scope_rejects_none() {
        // Site Admin MUST specify a site — "no filter" would leak
        // across site boundaries.
        let scope = DataScope::Sites(vec![site("langley")]);
        let result = require_site_filter(&scope, None);
        assert!(matches!(result, Err(AdminUiError::ScopeViolation)));
    }

    #[test]
    fn nist_ac3_site_filter_site_scope_accepts_own_site() {
        let scope = DataScope::Sites(vec![site("langley")]);
        assert!(require_site_filter(&scope, Some(&site("langley"))).is_ok());
    }

    #[test]
    fn nist_ac3_site_filter_site_scope_rejects_other_site() {
        let scope = DataScope::Sites(vec![site("langley")]);
        let result = require_site_filter(&scope, Some(&site("ramstein")));
        assert!(matches!(result, Err(AdminUiError::ScopeViolation)));
    }

    // ── require_can_grant_role (role-ladder enforcement) ─────────────

    #[test]
    fn nist_ac6_fleet_admin_can_grant_any_role() {
        let caller = vec![Role::FleetAdmin];
        for target in [
            Role::User,
            Role::Auditor,
            Role::FleetAdmin,
            Role::SiteAdmin(site("langley")),
        ] {
            assert!(require_can_grant_role(&caller, &target).is_ok(),
                "FleetAdmin should be able to grant {target:?}");
        }
    }

    #[test]
    fn nist_ac6_site_admin_cannot_grant_fleet_admin() {
        // Evidence against the primary privilege-escalation vuln:
        // a SiteAdmin cannot promote anyone (including themself) to
        // FleetAdmin.
        let caller = vec![Role::SiteAdmin(site("langley"))];
        let result = require_can_grant_role(&caller, &Role::FleetAdmin);
        assert!(matches!(result, Err(AdminUiError::AccessDenied)));
    }

    #[test]
    fn nist_ac6_site_admin_cannot_grant_auditor() {
        let caller = vec![Role::SiteAdmin(site("langley"))];
        let result = require_can_grant_role(&caller, &Role::Auditor);
        assert!(matches!(result, Err(AdminUiError::AccessDenied)));
    }

    #[test]
    fn nist_ac6_site_admin_cannot_grant_cross_site_site_admin() {
        let caller = vec![Role::SiteAdmin(site("langley"))];
        let result = require_can_grant_role(
            &caller,
            &Role::SiteAdmin(site("ramstein")),
        );
        assert!(matches!(result, Err(AdminUiError::AccessDenied)));
    }

    #[test]
    fn nist_ac6_site_admin_can_grant_own_site_site_admin() {
        let caller = vec![Role::SiteAdmin(site("langley"))];
        assert!(require_can_grant_role(
            &caller,
            &Role::SiteAdmin(site("langley")),
        )
        .is_ok());
    }

    #[test]
    fn nist_ac6_site_admin_can_grant_user() {
        let caller = vec![Role::SiteAdmin(site("langley"))];
        assert!(require_can_grant_role(&caller, &Role::User).is_ok());
    }

    #[test]
    fn nist_ac6_auditor_alone_cannot_grant_anything() {
        // Auditor is a read-only role; letting it mutate role
        // assignments would defeat separation of duties.
        let caller = vec![Role::Auditor];
        for target in [
            Role::User,
            Role::Auditor,
            Role::FleetAdmin,
            Role::SiteAdmin(site("langley")),
        ] {
            let result = require_can_grant_role(&caller, &target);
            assert!(matches!(result, Err(AdminUiError::AccessDenied)),
                "Auditor should not be able to grant {target:?}");
        }
    }

    #[test]
    fn nist_ac6_plain_user_cannot_grant_anything() {
        let caller = vec![Role::User];
        let result = require_can_grant_role(&caller, &Role::User);
        assert!(matches!(result, Err(AdminUiError::AccessDenied)));
    }
}
