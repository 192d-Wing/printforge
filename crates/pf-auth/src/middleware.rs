// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Axum middleware extractors for authentication and authorization.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, IA-2 — Identification and Authentication
//!
//! Provides `RequireAuth` and `RequireRole` extractors for use in Axum
//! route handlers. These extractors validate the JWT bearer token and
//! check role-based access control.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use pf_common::identity::Role;
use serde::{Deserialize, Serialize};

use crate::jwt::PrintForgeClaims;

/// Error type returned by auth middleware when authentication or
/// authorization fails. Implements `IntoResponse` for Axum integration.
///
/// Messages are intentionally vague to prevent information leakage.
#[derive(Debug)]
pub enum AuthRejection {
    /// No valid bearer token was provided.
    MissingToken,
    /// Token was present but invalid (expired, malformed, bad signature).
    InvalidToken,
    /// Token was valid but the user lacks the required role.
    InsufficientRole,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::MissingToken => (StatusCode::UNAUTHORIZED, "authentication required"),
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, "authentication failed"),
            Self::InsufficientRole => (StatusCode::FORBIDDEN, "access denied"),
        };
        (status, msg).into_response()
    }
}

/// Authenticated user identity extracted from a valid JWT bearer token.
///
/// **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication
///
/// Use this as an Axum extractor in route handlers:
///
/// ```ignore
/// async fn my_handler(auth: RequireAuth) -> impl IntoResponse {
///     let edipi = &auth.claims.sub;
///     // ...
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequireAuth {
    /// The validated JWT claims.
    pub claims: PrintForgeClaims,
}

impl<S> FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    /// Extract and validate the JWT bearer token from the `Authorization` header.
    ///
    /// The actual JWT validation requires access to the `JwtKeyPair` and `JwtConfig`,
    /// which in production are provided via Axum state. This implementation extracts
    /// the token string; full validation is wired up in the application layer.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the Authorization header.
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthRejection::MissingToken)?;

        // Must be a Bearer token.
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthRejection::MissingToken)?;

        if token.is_empty() {
            return Err(AuthRejection::MissingToken);
        }

        // In a full implementation, this would:
        // 1. Retrieve JwtKeyPair and JwtConfig from Axum state
        // 2. Call jwt::validate_token(config, key_pair, token)
        // 3. Return the claims
        //
        // For now, we decode without verification to establish the type structure.
        // The actual wiring happens in pf-api-gateway.
        let _ = token;
        Err(AuthRejection::InvalidToken)
    }
}

/// Role-based access control check.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// Verifies that the authenticated user holds at least one of the
/// required roles.
#[derive(Debug, Clone)]
pub struct RequireRole {
    /// The authenticated user's claims (extracted from `RequireAuth`).
    pub claims: PrintForgeClaims,
}

impl RequireRole {
    /// Check whether the user's claims include at least one of the given roles.
    ///
    /// # Errors
    ///
    /// Returns `AuthRejection::InsufficientRole` if the user has none of the
    /// required roles.
    pub fn check_roles(claims: &PrintForgeClaims, required: &[Role]) -> Result<(), AuthRejection> {
        for required_role in required {
            let role_str = role_to_string(required_role);
            if claims.roles.contains(&role_str) {
                return Ok(());
            }
        }
        Err(AuthRejection::InsufficientRole)
    }
}

/// Convert a `Role` enum to its string representation for JWT claims.
#[must_use]
pub fn role_to_string(role: &Role) -> String {
    match role {
        Role::User => "User".to_string(),
        Role::SiteAdmin(site) => format!("SiteAdmin:{}", site.0),
        Role::FleetAdmin => "FleetAdmin".to_string(),
        Role::Auditor => "Auditor".to_string(),
    }
}

/// Parse a role string back into a `Role` enum.
///
/// # Errors
///
/// Returns `None` if the string does not match any known role format.
#[must_use]
pub fn role_from_string(s: &str) -> Option<Role> {
    match s {
        "User" => Some(Role::User),
        "FleetAdmin" => Some(Role::FleetAdmin),
        "Auditor" => Some(Role::Auditor),
        other if other.starts_with("SiteAdmin:") => {
            let site_id = other.strip_prefix("SiteAdmin:")?;
            Some(Role::SiteAdmin(pf_common::identity::SiteId(
                site_id.to_string(),
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use pf_common::identity::SiteId;

    use super::*;
    use crate::jwt::TokenScope;

    fn test_claims(roles: Vec<String>) -> PrintForgeClaims {
        PrintForgeClaims {
            sub: "1234567890".to_string(),
            iss: "printforge".to_string(),
            aud: "printforge-api".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nbf: 1_000_000_000,
            jti: "test-jti".to_string(),
            scope: TokenScope::Session,
            roles,
            printer_id: None,
        }
    }

    #[test]
    fn nist_ac3_check_roles_allows_matching_role() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: User with FleetAdmin role passes FleetAdmin check.
        let claims = test_claims(vec!["FleetAdmin".to_string()]);
        let result = RequireRole::check_roles(&claims, &[Role::FleetAdmin]);
        assert!(result.is_ok());
    }

    #[test]
    fn nist_ac3_check_roles_rejects_missing_role() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: User with only User role is denied FleetAdmin access.
        let claims = test_claims(vec!["User".to_string()]);
        let result = RequireRole::check_roles(&claims, &[Role::FleetAdmin]);
        assert!(matches!(result, Err(AuthRejection::InsufficientRole)));
    }

    #[test]
    fn check_roles_accepts_any_of_required() {
        let claims = test_claims(vec!["Auditor".to_string()]);
        let result = RequireRole::check_roles(&claims, &[Role::FleetAdmin, Role::Auditor]);
        assert!(result.is_ok());
    }

    #[test]
    fn role_round_trip() {
        let roles = vec![
            Role::User,
            Role::FleetAdmin,
            Role::Auditor,
            Role::SiteAdmin(SiteId("TINKER-AFB".to_string())),
        ];

        for role in &roles {
            let s = role_to_string(role);
            let parsed = role_from_string(&s);
            assert_eq!(parsed.as_ref(), Some(role));
        }
    }

    #[test]
    fn role_from_string_returns_none_for_unknown() {
        assert_eq!(role_from_string("SuperAdmin"), None);
    }

    #[test]
    fn auth_rejection_responses() {
        // Verify that rejections produce correct status codes.
        let resp = AuthRejection::MissingToken.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = AuthRejection::InvalidToken.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = AuthRejection::InsufficientRole.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
