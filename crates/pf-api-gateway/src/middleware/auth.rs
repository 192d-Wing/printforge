// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Authentication extractor: validates JWT and extracts `Identity`.
//!
//! **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication,
//! AC-3 — Access Enforcement

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

use pf_common::identity::{Edipi, Identity, Role, SiteId};

use crate::server::AppState;

/// JWT claims expected from `pf-auth` issued tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintForgeClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub scope: String,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub printer_id: Option<String>,
}

/// Extractor that requires a valid authenticated identity on the request.
///
/// Validates the JWT from the `Authorization: Bearer <token>` header,
/// checks signature, expiry, issuer, and audience, then extracts the
/// caller's `Identity`.
///
/// **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication
#[derive(Debug, Clone)]
pub struct RequireAuth(pub Identity);

/// Rejection returned when authentication fails.
#[derive(Debug)]
pub struct AuthRejection;

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "authentication required").into_response()
    }
}

/// Extract the Bearer token from the Authorization header.
fn extract_bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    let token = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Parse a role string into the `Role` enum.
fn parse_role(s: &str) -> Option<Role> {
    match s {
        "User" => Some(Role::User),
        "FleetAdmin" => Some(Role::FleetAdmin),
        "Auditor" => Some(Role::Auditor),
        other if other.starts_with("SiteAdmin:") => {
            let site = other.strip_prefix("SiteAdmin:")?;
            Some(Role::SiteAdmin(SiteId(site.to_string())))
        }
        _ => None,
    }
}

/// Validate a JWT and extract the identity.
///
/// **NIST 800-53 Rev 5:** IA-2, IA-5
fn validate_and_extract(
    token: &str,
    decoding_key: &DecodingKey,
    issuer: &str,
    audience: &str,
) -> Result<Identity, AuthRejection> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data = decode::<PrintForgeClaims>(token, decoding_key, &validation)
        .map_err(|e| {
            tracing::warn!(error = %e, "JWT validation failed");
            AuthRejection
        })?;

    let claims = token_data.claims;

    let edipi = Edipi::new(&claims.sub).map_err(|_| {
        tracing::warn!("JWT sub claim is not a valid EDIPI");
        AuthRejection
    })?;

    let roles: Vec<Role> = claims
        .roles
        .iter()
        .filter_map(|s| parse_role(s))
        .collect();

    if roles.is_empty() {
        // Every user must have at least one role.
        tracing::warn!("JWT contains no valid roles");
        return Err(AuthRejection);
    }

    Ok(Identity {
        edipi,
        name: String::new(),
        org: String::new(),
        roles,
    })
}

impl FromRequestParts<AppState> for RequireAuth {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts).ok_or(AuthRejection)?;

        let decoding_key = state
            .jwt_decoding_key
            .as_ref()
            .ok_or_else(|| {
                tracing::error!("JWT decoding key not configured");
                AuthRejection
            })?;

        let identity = validate_and_extract(
            token,
            decoding_key,
            &state.config.jwt.issuer,
            &state.config.jwt.audience,
        )?;

        Ok(Self(identity))
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

    #[test]
    fn nist_ac3_is_admin_detects_fleet_admin() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
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

    #[test]
    fn parse_role_handles_all_variants() {
        assert_eq!(parse_role("User"), Some(Role::User));
        assert_eq!(parse_role("FleetAdmin"), Some(Role::FleetAdmin));
        assert_eq!(parse_role("Auditor"), Some(Role::Auditor));
        assert_eq!(
            parse_role("SiteAdmin:SITE-001"),
            Some(Role::SiteAdmin(SiteId("SITE-001".to_string())))
        );
        assert_eq!(parse_role("Invalid"), None);
    }

    #[test]
    fn extract_bearer_token_rejects_missing_header() {
        let parts = axum::http::Request::builder()
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(extract_bearer_token(&parts).is_none());
    }

    #[test]
    fn extract_bearer_token_rejects_empty_token() {
        let parts = axum::http::Request::builder()
            .header("Authorization", "Bearer ")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(extract_bearer_token(&parts).is_none());
    }

    #[test]
    fn extract_bearer_token_extracts_valid_token() {
        let parts = axum::http::Request::builder()
            .header("Authorization", "Bearer eyJ0eXAiOi.test.token")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(
            extract_bearer_token(&parts),
            Some("eyJ0eXAiOi.test.token")
        );
    }

    // JWT validation integration tests that use real key pairs
    // are in tests/integration_auth.rs
}
