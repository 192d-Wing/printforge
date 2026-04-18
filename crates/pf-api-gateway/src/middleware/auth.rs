// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Authentication wiring for the gateway.
//!
//! The JWT extractor and `RequireAuth` type live in [`pf_auth::middleware`] and
//! are generic over any state implementing [`HasJwtConfig`]. This module
//! implements that trait for [`AppState`] and re-exports the extractor so
//! gateway route handlers can continue to `use crate::middleware::auth::RequireAuth;`.
//!
//! Gateway-local helpers for role checks (`is_admin`, `satisfies_role`,
//! `MinRole`, `RoleRejection`) stay here — they are not JWT-specific.
//!
//! **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication,
//! AC-3 — Access Enforcement

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::DecodingKey;
use pf_common::identity::{Identity, Role};
use pf_auth::middleware::HasJwtConfig;
use serde::Serialize;

pub use pf_auth::middleware::{AuthRejection, RequireAuth};

use crate::server::AppState;

impl HasJwtConfig for AppState {
    fn jwt_decoding_key(&self) -> Option<&DecodingKey> {
        self.jwt_decoding_key.as_deref()
    }

    fn jwt_issuer(&self) -> &str {
        &self.config.jwt.issuer
    }

    fn jwt_audience(&self) -> &str {
        &self.config.jwt.audience
    }
}

/// Check whether an identity holds an admin-level role (`FleetAdmin` or `SiteAdmin`).
#[must_use]
pub fn is_admin(identity: &Identity) -> bool {
    identity
        .roles
        .iter()
        .any(|r| matches!(r, Role::FleetAdmin | Role::SiteAdmin(_)))
}

/// Check whether an identity holds the `Auditor` role.
#[must_use]
pub fn is_auditor(identity: &Identity) -> bool {
    identity.roles.iter().any(|r| matches!(r, Role::Auditor))
}

/// Minimum role level for RBAC checks.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// Role hierarchy (higher includes lower):
/// `FleetAdmin` > `SiteAdmin` > `User`
///
/// `Auditor` is a separate axis — it grants read access to audit data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinRole {
    /// Any authenticated user.
    User,
    /// Site administrator or higher.
    SiteAdmin,
    /// Fleet administrator.
    FleetAdmin,
    /// Auditor role (orthogonal to admin hierarchy).
    Auditor,
}

/// Check whether an identity satisfies a minimum role requirement.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[must_use]
pub fn satisfies_role(identity: &Identity, min: MinRole) -> bool {
    match min {
        MinRole::User => true,
        MinRole::SiteAdmin => identity
            .roles
            .iter()
            .any(|r| matches!(r, Role::SiteAdmin(_) | Role::FleetAdmin)),
        MinRole::FleetAdmin => identity.roles.iter().any(|r| matches!(r, Role::FleetAdmin)),
        MinRole::Auditor => identity
            .roles
            .iter()
            .any(|r| matches!(r, Role::Auditor | Role::FleetAdmin)),
    }
}

/// Rejection returned when authorization fails (insufficient role).
#[derive(Debug, Serialize)]
pub struct RoleRejection;

impl IntoResponse for RoleRejection {
    fn into_response(self) -> Response {
        (StatusCode::FORBIDDEN, "access denied").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::identity::{Edipi, SiteId};

    #[test]
    fn nist_ac3_is_admin_detects_fleet_admin() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::FleetAdmin],
        };
        assert!(is_admin(&identity));
    }

    #[test]
    fn nist_ac3_is_admin_detects_site_admin() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::SiteAdmin(SiteId("SITE-001".to_string()))],
        };
        assert!(is_admin(&identity));
    }

    #[test]
    fn nist_ac3_is_admin_rejects_user() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::User],
        };
        assert!(!is_admin(&identity));
    }

    #[test]
    fn nist_ac3_is_auditor_detects_auditor() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::Auditor],
        };
        assert!(is_auditor(&identity));
    }

    #[test]
    fn nist_ac3_fleet_admin_satisfies_all_levels() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::FleetAdmin],
        };
        assert!(satisfies_role(&identity, MinRole::User));
        assert!(satisfies_role(&identity, MinRole::SiteAdmin));
        assert!(satisfies_role(&identity, MinRole::FleetAdmin));
        assert!(satisfies_role(&identity, MinRole::Auditor));
    }

    #[test]
    fn nist_ac3_site_admin_cannot_access_fleet_admin() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::SiteAdmin(SiteId("SITE-001".to_string()))],
        };
        assert!(satisfies_role(&identity, MinRole::User));
        assert!(satisfies_role(&identity, MinRole::SiteAdmin));
        assert!(!satisfies_role(&identity, MinRole::FleetAdmin));
    }

    #[test]
    fn nist_ac3_user_cannot_access_admin_routes() {
        let identity = Identity {
            edipi: Edipi::new("1234567890").unwrap(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::User],
        };
        assert!(satisfies_role(&identity, MinRole::User));
        assert!(!satisfies_role(&identity, MinRole::SiteAdmin));
        assert!(!satisfies_role(&identity, MinRole::FleetAdmin));
        assert!(!satisfies_role(&identity, MinRole::Auditor));
    }
}
