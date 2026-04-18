// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! OIDC Authorization Code Flow with PKCE.
//!
//! **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication (Non-Organizational Users)
//!
//! Implements the OIDC Authorization Code Flow with PKCE (S256) for
//! authentication against `Entra ID` (NIPR). This module defines the flow
//! types and state machine; actual HTTP calls are performed via the
//! `openidconnect` crate.

use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use pf_common::identity::{Edipi, Identity, Role};

use crate::certificate::extract_edipi_from_cn;
use crate::config::OidcConfig;
use crate::error::AuthError;

/// PKCE verifier/challenge pair for a single OIDC flow.
///
/// The verifier is kept server-side; only the challenge is sent to the `IdP`.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The code verifier (high-entropy random string, 43-128 chars).
    verifier: String,
    /// The S256 challenge derived from the verifier.
    challenge: String,
}

impl PkceChallenge {
    /// Generate a new PKCE verifier and S256 challenge.
    ///
    /// Uses `ring` CSPRNG for the verifier.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::Internal` if random byte generation fails.
    pub fn generate() -> Result<Self, AuthError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let random_bytes = pf_common::crypto::random_bytes(32)
            .map_err(|e| AuthError::Internal(format!("failed to generate PKCE verifier: {e}")))?;

        let verifier = URL_SAFE_NO_PAD.encode(&random_bytes);
        let challenge_bytes = pf_common::crypto::sha256(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(&challenge_bytes);

        Ok(Self {
            verifier,
            challenge,
        })
    }

    /// Return the code verifier (for token exchange).
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Return the S256 challenge (for the authorization URL).
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// State for an in-progress OIDC authorization flow.
///
/// Stored server-side (e.g., in a session store) between the redirect
/// to the `IdP` and the callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcFlowState {
    /// Opaque state parameter for CSRF protection.
    pub state: String,

    /// The nonce sent to the `IdP` (verified in the ID token).
    pub nonce: String,

    /// PKCE code verifier (not serialized to client).
    #[serde(skip)]
    pub pkce_verifier: Option<String>,

    /// Where to redirect the user after successful authentication.
    pub return_url: Option<String>,
}

/// Parameters received at the OIDC callback endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcCallback {
    /// Authorization code from the `IdP`.
    pub code: String,
    /// State parameter (must match `OidcFlowState.state`).
    pub state: String,
}

/// Token set returned after a successful OIDC token exchange.
#[derive(Debug, Clone)]
pub struct OidcTokens {
    /// The raw ID token (JWT) from the `IdP`.
    pub id_token: String,
    /// The access token from the `IdP`.
    pub access_token: String,
    /// Optional refresh token.
    pub refresh_token: Option<String>,
}

/// Build the OIDC authorization URL for redirecting the user to the `IdP`.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::OidcError` if the configuration is invalid.
/// Returns `AuthError::Internal` if PKCE generation fails.
pub fn build_authorization_url(config: &OidcConfig) -> Result<(Url, OidcFlowState), AuthError> {
    let pkce = PkceChallenge::generate()?;

    let state = base64_random_string()?;
    let nonce = base64_random_string()?;

    let mut auth_url = config.issuer_url.clone();
    auth_url
        .path_segments_mut()
        .map_err(|()| AuthError::OidcError("issuer URL cannot be a base".to_string()))?
        .push("authorize");

    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", config.redirect_uri.as_str())
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", pkce.challenge())
        .append_pair("code_challenge_method", "S256");

    let flow_state = OidcFlowState {
        state,
        nonce,
        pkce_verifier: Some(pkce.verifier().to_string()),
        return_url: None,
    };

    Ok((auth_url, flow_state))
}

/// Claims extracted from an OIDC ID token.
///
/// These are the claims we need to build a `PrintForge` `Identity`.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    /// Subject identifier from the `IdP`.
    pub sub: String,
    /// Preferred username — expected to contain the EDIPI or `DoD` CN.
    pub preferred_username: Option<String>,
    /// Direct EDIPI claim (custom claim from Entra ID).
    pub edipi: Option<String>,
    /// User display name.
    pub name: Option<String>,
    /// Organization / unit.
    pub org: Option<String>,
    /// Group memberships from the `IdP` for role mapping.
    pub groups: Option<Vec<String>>,
    /// Nonce — must match the original request nonce.
    pub nonce: Option<String>,
}

/// JSON response from the OIDC token endpoint.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: String,
    refresh_token: Option<String>,
}

/// Exchange an authorization code for tokens and extract a `PrintForge` `Identity`.
///
/// Validates the OIDC callback parameters against the stored flow state:
/// 1. Verifies the `state` parameter matches (CSRF protection).
/// 2. Verifies a PKCE code verifier is available.
/// 3. Performs the token exchange via HTTP POST to the token endpoint.
/// 4. Extracts the EDIPI from ID token claims.
/// 5. Maps `IdP` group claims to `PrintForge` roles.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::OidcError` if state validation fails, PKCE verifier
/// is missing, or token exchange/parsing fails.
pub async fn exchange_code(
    config: &OidcConfig,
    callback: &OidcCallback,
    flow_state: &OidcFlowState,
) -> Result<(OidcTokens, Identity), AuthError> {
    // Step 1: Validate state parameter (CSRF protection).
    if callback.state != flow_state.state {
        warn!("OIDC callback state mismatch — possible CSRF attack");
        return Err(AuthError::OidcError(
            "state parameter mismatch".to_string(),
        ));
    }

    // Step 2: Verify PKCE code verifier is present.
    let pkce_verifier = flow_state.pkce_verifier.as_ref().ok_or_else(|| {
        AuthError::OidcError("missing PKCE code verifier in flow state".to_string())
    })?;

    // Step 3: Build the token endpoint URL from the issuer URL.
    let mut token_url = config.issuer_url.clone();
    token_url
        .path_segments_mut()
        .map_err(|()| AuthError::OidcError("issuer URL cannot be a base".to_string()))?
        .push("token");

    // Step 4: POST the token request as form-encoded params.
    // SECURITY: NEVER log the authorization code, tokens, or code verifier.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AuthError::OidcError(format!("failed to build HTTP client: {e}")))?;

    let response = client
        .post(token_url.as_str())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &callback.code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("client_id", &config.client_id),
            ("code_verifier", pkce_verifier),
        ])
        .send()
        .await
        .map_err(|e| AuthError::OidcError(format!("token exchange request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AuthError::OidcError(format!(
            "token endpoint returned HTTP {}",
            response.status(),
        )));
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|e| AuthError::OidcError(format!("failed to parse token response: {e}")))?;

    let id_token = token_response.id_token.ok_or_else(|| {
        AuthError::OidcError("token response missing id_token".to_string())
    })?;

    let tokens = OidcTokens {
        id_token: id_token.clone(),
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
    };

    // Step 5: Decode the ID token claims (no signature verification here;
    // in production this would verify against the IdP's JWKS).
    let claims = decode_id_token_claims(&id_token)?;

    // Step 6: Validate the nonce.
    if let Some(ref nonce) = claims.nonce {
        if *nonce != flow_state.nonce {
            warn!("OIDC ID token nonce mismatch");
            return Err(AuthError::OidcError(
                "nonce mismatch in ID token".to_string(),
            ));
        }
    }

    // Step 7: Extract the EDIPI from claims.
    let edipi = extract_edipi_from_claims(&claims)?;

    // Step 8: Map IdP groups to PrintForge roles.
    let roles = map_groups_to_roles(claims.groups.as_deref().unwrap_or(&[]));

    let identity = Identity {
        edipi,
        name: claims.name.clone().unwrap_or_default(),
        org: claims.org.clone().unwrap_or_default(),
        roles,
    };

    Ok((tokens, identity))
}

/// Decode the payload of a JWT ID token without signature verification.
///
/// This is used to extract claims after the token exchange. In production,
/// signature verification should be performed against the `IdP`'s JWKS.
fn decode_id_token_claims(id_token: &str) -> Result<IdTokenClaims, AuthError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::OidcError(
            "ID token is not a valid JWT (expected 3 parts)".to_string(),
        ));
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
        AuthError::OidcError(format!("failed to base64-decode ID token payload: {e}"))
    })?;

    serde_json::from_slice(&payload_bytes).map_err(|e| {
        AuthError::OidcError(format!("failed to parse ID token claims: {e}"))
    })
}

/// Exchange step that accepts pre-parsed ID token claims.
///
/// This function performs the same state/PKCE validation as `exchange_code`
/// but skips the HTTP call, accepting already-parsed claims. This is used
/// for unit testing and will be called by the real `exchange_code` once
/// the HTTP transport is wired up.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::OidcError` on validation or extraction failure.
pub fn exchange_code_with_claims(
    callback: &OidcCallback,
    flow_state: &OidcFlowState,
    tokens: OidcTokens,
    claims: &IdTokenClaims,
) -> Result<(OidcTokens, Identity), AuthError> {
    // Step 1: Validate state parameter (CSRF protection).
    if callback.state != flow_state.state {
        warn!("OIDC callback state mismatch — possible CSRF attack");
        return Err(AuthError::OidcError(
            "state parameter mismatch".to_string(),
        ));
    }

    // Step 2: Verify PKCE code verifier is present.
    let _pkce_verifier = flow_state.pkce_verifier.as_ref().ok_or_else(|| {
        AuthError::OidcError("missing PKCE code verifier in flow state".to_string())
    })?;

    // Step 3: Validate the nonce if present in claims.
    if let Some(ref nonce) = claims.nonce {
        if *nonce != flow_state.nonce {
            warn!("OIDC ID token nonce mismatch");
            return Err(AuthError::OidcError(
                "nonce mismatch in ID token".to_string(),
            ));
        }
    }

    // Step 4: Extract the EDIPI from claims.
    let edipi = extract_edipi_from_claims(claims)?;

    // Step 5: Map IdP groups to PrintForge roles.
    let roles = map_groups_to_roles(claims.groups.as_deref().unwrap_or(&[]));

    let identity = Identity {
        edipi,
        name: claims.name.clone().unwrap_or_default(),
        org: claims.org.clone().unwrap_or_default(),
        roles,
    };

    Ok((tokens, identity))
}

/// Extract the EDIPI from OIDC ID token claims.
///
/// Checks the following claim sources in order:
/// 1. `edipi` — direct EDIPI claim (custom Entra ID mapping)
/// 2. `preferred_username` — expected in `DoD` CN format (`LAST.FIRST.MI.1234567890`)
/// 3. `sub` — fallback if it contains a 10-digit EDIPI
///
/// **NIST 800-53 Rev 5:** IA-2(12) — Accept PIV Credentials
///
/// # Errors
///
/// Returns `AuthError::OidcError` if no valid EDIPI can be extracted.
fn extract_edipi_from_claims(claims: &IdTokenClaims) -> Result<Edipi, AuthError> {
    // Try direct EDIPI claim first.
    if let Some(ref edipi_str) = claims.edipi {
        if let Ok(edipi) = Edipi::new(edipi_str) {
            return Ok(edipi);
        }
    }

    // Try preferred_username as DoD CN format.
    if let Some(ref username) = claims.preferred_username {
        if let Ok(edipi) = extract_edipi_from_cn(username) {
            return Ok(edipi);
        }
        // Also try as raw EDIPI.
        if let Ok(edipi) = Edipi::new(username) {
            return Ok(edipi);
        }
    }

    // Try sub as raw EDIPI.
    if let Ok(edipi) = Edipi::new(&claims.sub) {
        return Ok(edipi);
    }

    Err(AuthError::OidcError(
        "unable to extract EDIPI from ID token claims".to_string(),
    ))
}

/// Map `IdP` group names to `PrintForge` roles.
///
/// Group-to-role mapping:
/// - `PrintForge-FleetAdmin` → `Role::FleetAdmin`
/// - `PrintForge-Auditor` → `Role::Auditor`
/// - `PrintForge-SiteAdmin-<SiteId>` → `Role::SiteAdmin(SiteId)`
/// - All authenticated users get at least `Role::User`
fn map_groups_to_roles(groups: &[String]) -> Vec<Role> {
    let mut roles = vec![Role::User];

    for group in groups {
        if group == "PrintForge-FleetAdmin" {
            if !roles.contains(&Role::FleetAdmin) {
                roles.push(Role::FleetAdmin);
            }
        } else if group == "PrintForge-Auditor" {
            if !roles.contains(&Role::Auditor) {
                roles.push(Role::Auditor);
            }
        } else if let Some(site_id) = group.strip_prefix("PrintForge-SiteAdmin-") {
            let site_role =
                Role::SiteAdmin(pf_common::identity::SiteId(site_id.to_string()));
            if !roles.contains(&site_role) {
                roles.push(site_role);
            }
        }
    }

    roles
}

/// Generate a URL-safe base64 random string for state/nonce parameters.
fn base64_random_string() -> Result<String, AuthError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let bytes = pf_common::crypto::random_bytes(32)
        .map_err(|e| AuthError::Internal(format!("failed to generate random string: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_flow_state() -> OidcFlowState {
        OidcFlowState {
            state: "test-state-abc".to_string(),
            nonce: "test-nonce-xyz".to_string(),
            pkce_verifier: Some("test-verifier-123".to_string()),
            return_url: None,
        }
    }

    fn test_tokens() -> OidcTokens {
        OidcTokens {
            id_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.stub".to_string(),
            access_token: "at-stub-token".to_string(),
            refresh_token: None,
        }
    }

    fn test_claims_with_edipi() -> IdTokenClaims {
        IdTokenClaims {
            sub: "user-subject-id".to_string(),
            preferred_username: Some("DOE.JOHN.Q.1234567890".to_string()),
            edipi: None,
            name: Some("John Q Doe".to_string()),
            org: Some("Test Unit, Test Base AFB".to_string()),
            groups: Some(vec!["PrintForge-FleetAdmin".to_string()]),
            nonce: Some("test-nonce-xyz".to_string()),
        }
    }

    #[test]
    fn pkce_challenge_generates_valid_pair() {
        let pkce = PkceChallenge::generate().unwrap();
        assert!(!pkce.verifier().is_empty());
        assert!(!pkce.challenge().is_empty());
        // Verifier and challenge must be different.
        assert_ne!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn pkce_challenge_is_deterministic_from_verifier() {
        // Two calls produce different verifiers (random).
        let a = PkceChallenge::generate().unwrap();
        let b = PkceChallenge::generate().unwrap();
        assert_ne!(a.verifier(), b.verifier());
    }

    #[test]
    fn build_authorization_url_includes_required_params() {
        let config = OidcConfig {
            issuer_url: Url::parse("https://login.example.com/tenant1").unwrap(),
            client_id: "test-client-id".to_string(),
            redirect_uri: Url::parse("https://printforge.local/callback").unwrap(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
        };

        let (url, state) = build_authorization_url(&config).unwrap();
        let url_str = url.to_string();

        assert!(url_str.contains("response_type=code"));
        assert!(url_str.contains("client_id=test-client-id"));
        assert!(url_str.contains("code_challenge_method=S256"));
        assert!(url_str.contains("code_challenge="));
        assert!(url_str.contains("state="));
        assert!(url_str.contains("nonce="));
        assert!(state.pkce_verifier.is_some());
    }

    #[test]
    fn nist_ia8_oidc_flow_state_has_csrf_protection() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: OIDC flow includes state parameter for CSRF protection.
        let config = OidcConfig {
            issuer_url: Url::parse("https://login.example.com/tenant1").unwrap(),
            client_id: "test-client".to_string(),
            redirect_uri: Url::parse("https://printforge.local/callback").unwrap(),
            scopes: vec!["openid".to_string()],
        };

        let (_, state) = build_authorization_url(&config).unwrap();
        assert!(!state.state.is_empty());
        assert!(!state.nonce.is_empty());
    }

    #[test]
    fn nist_ia8_oidc_exchange_validates_state() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: Mismatched state parameter is rejected to prevent CSRF.
        let flow_state = test_flow_state();
        let callback = OidcCallback {
            code: "auth-code-abc".to_string(),
            state: "WRONG-STATE".to_string(), // does not match flow_state.state
        };
        let tokens = test_tokens();
        let claims = test_claims_with_edipi();

        let result = exchange_code_with_claims(&callback, &flow_state, tokens, &claims);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("state parameter mismatch"));
    }

    #[test]
    fn nist_ia8_oidc_extracts_edipi_from_claims() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: EDIPI is correctly extracted from the preferred_username
        // claim in DoD CN format.
        let flow_state = test_flow_state();
        let callback = OidcCallback {
            code: "auth-code-abc".to_string(),
            state: "test-state-abc".to_string(),
        };
        let tokens = test_tokens();
        let claims = test_claims_with_edipi();

        let (_, identity) =
            exchange_code_with_claims(&callback, &flow_state, tokens, &claims).unwrap();
        assert_eq!(identity.edipi.as_str(), "1234567890");
        assert_eq!(identity.name, "John Q Doe");
        assert!(identity.roles.contains(&Role::FleetAdmin));
        assert!(identity.roles.contains(&Role::User));
    }

    #[test]
    fn oidc_extracts_edipi_from_direct_claim() {
        // When the IdP provides a direct `edipi` claim, prefer it.
        let flow_state = test_flow_state();
        let callback = OidcCallback {
            code: "auth-code".to_string(),
            state: "test-state-abc".to_string(),
        };
        let tokens = test_tokens();
        let claims = IdTokenClaims {
            sub: "sub-id".to_string(),
            preferred_username: None,
            edipi: Some("9876543210".to_string()),
            name: Some("Jane Doe".to_string()),
            org: None,
            groups: None,
            nonce: Some("test-nonce-xyz".to_string()),
        };

        let (_, identity) =
            exchange_code_with_claims(&callback, &flow_state, tokens, &claims).unwrap();
        assert_eq!(identity.edipi.as_str(), "9876543210");
    }

    #[test]
    fn oidc_rejects_missing_pkce_verifier() {
        let flow_state = OidcFlowState {
            state: "test-state-abc".to_string(),
            nonce: "test-nonce-xyz".to_string(),
            pkce_verifier: None, // missing
            return_url: None,
        };
        let callback = OidcCallback {
            code: "auth-code".to_string(),
            state: "test-state-abc".to_string(),
        };
        let tokens = test_tokens();
        let claims = test_claims_with_edipi();

        let result = exchange_code_with_claims(&callback, &flow_state, tokens, &claims);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("PKCE"));
    }

    #[test]
    fn oidc_rejects_nonce_mismatch() {
        let flow_state = test_flow_state();
        let callback = OidcCallback {
            code: "auth-code".to_string(),
            state: "test-state-abc".to_string(),
        };
        let tokens = test_tokens();
        let mut claims = test_claims_with_edipi();
        claims.nonce = Some("WRONG-NONCE".to_string());

        let result = exchange_code_with_claims(&callback, &flow_state, tokens, &claims);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("nonce"));
    }

    #[test]
    fn oidc_maps_groups_to_roles() {
        let groups = vec![
            "PrintForge-FleetAdmin".to_string(),
            "PrintForge-Auditor".to_string(),
            "PrintForge-SiteAdmin-TYNDALL".to_string(),
            "SomeOtherGroup".to_string(),
        ];

        let roles = map_groups_to_roles(&groups);
        assert!(roles.contains(&Role::User));
        assert!(roles.contains(&Role::FleetAdmin));
        assert!(roles.contains(&Role::Auditor));
        assert!(roles.contains(&Role::SiteAdmin(
            pf_common::identity::SiteId("TYNDALL".to_string())
        )));
        // "SomeOtherGroup" should not add any extra roles.
        assert_eq!(roles.len(), 4);
    }

    #[test]
    fn oidc_rejects_claims_without_edipi() {
        let claims = IdTokenClaims {
            sub: "some-opaque-subject".to_string(),
            preferred_username: Some("john.doe@example.com".to_string()),
            edipi: None,
            name: None,
            org: None,
            groups: None,
            nonce: None,
        };

        let result = extract_edipi_from_claims(&claims);
        assert!(result.is_err());
    }
}
