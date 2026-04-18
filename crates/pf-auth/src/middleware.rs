// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Axum middleware extractors for authentication and authorization.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, IA-2 — Identification and Authentication
//!
//! Provides `RequireAuth` and `RequireRole` extractors. `RequireAuth` validates
//! a JWT bearer token from the `Authorization` header and extracts the caller's
//! [`Identity`]. To use it in a handler, your Axum state must implement
//! [`HasJwtConfig`].

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use pf_common::identity::{Edipi, Identity, Role, SiteId};

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

/// Trait implemented by Axum state types that carry the JWT verification
/// configuration needed by [`RequireAuth`].
///
/// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
pub trait HasJwtConfig {
    /// Ed25519 public key used to verify JWT signatures. `None` means no key
    /// is configured and every request will be rejected.
    fn jwt_decoding_key(&self) -> Option<&DecodingKey>;

    /// Expected `iss` claim.
    fn jwt_issuer(&self) -> &str;

    /// Expected `aud` claim.
    fn jwt_audience(&self) -> &str;
}

/// Authenticated user identity extracted from a valid JWT bearer token.
///
/// **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication
#[derive(Debug, Clone)]
pub struct RequireAuth(pub Identity);

impl<S> FromRequestParts<S> for RequireAuth
where
    S: HasJwtConfig + Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts).ok_or(AuthRejection::MissingToken)?;

        let decoding_key = state.jwt_decoding_key().ok_or_else(|| {
            tracing::error!("JWT decoding key not configured");
            AuthRejection::InvalidToken
        })?;

        let identity = validate_and_extract(
            token,
            decoding_key,
            state.jwt_issuer(),
            state.jwt_audience(),
        )?;

        Ok(Self(identity))
    }
}

fn extract_bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}

fn parse_role_str(s: &str) -> Option<Role> {
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

    let token_data = decode::<PrintForgeClaims>(token, decoding_key, &validation).map_err(|e| {
        tracing::warn!(error = %e, "JWT validation failed");
        AuthRejection::InvalidToken
    })?;

    let claims = token_data.claims;

    let edipi = Edipi::new(&claims.sub).map_err(|_| {
        tracing::warn!("JWT sub claim is not a valid EDIPI");
        AuthRejection::InvalidToken
    })?;

    let roles: Vec<Role> = claims.roles.iter().filter_map(|s| parse_role_str(s)).collect();

    if roles.is_empty() {
        tracing::warn!("JWT contains no valid roles");
        return Err(AuthRejection::InvalidToken);
    }

    Ok(Identity {
        edipi,
        name: String::new(),
        org: String::new(),
        roles,
    })
}

/// Role-based access control check.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[derive(Debug, Clone)]
pub struct RequireRole;

impl RequireRole {
    /// Check whether the given claims include at least one of the required roles.
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
#[must_use]
pub fn role_from_string(s: &str) -> Option<Role> {
    parse_role_str(s)
}

#[cfg(test)]
mod tests {
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
        let claims = test_claims(vec!["FleetAdmin".to_string()]);
        let result = RequireRole::check_roles(&claims, &[Role::FleetAdmin]);
        assert!(result.is_ok());
    }

    #[test]
    fn nist_ac3_check_roles_rejects_missing_role() {
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
        let resp = AuthRejection::MissingToken.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = AuthRejection::InvalidToken.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = AuthRejection::InsufficientRole.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn parse_role_handles_all_variants() {
        assert_eq!(parse_role_str("User"), Some(Role::User));
        assert_eq!(parse_role_str("FleetAdmin"), Some(Role::FleetAdmin));
        assert_eq!(parse_role_str("Auditor"), Some(Role::Auditor));
        assert_eq!(
            parse_role_str("SiteAdmin:SITE-001"),
            Some(Role::SiteAdmin(SiteId("SITE-001".to_string())))
        );
        assert_eq!(parse_role_str("Invalid"), None);
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
        assert_eq!(extract_bearer_token(&parts), Some("eyJ0eXAiOi.test.token"));
    }
}
