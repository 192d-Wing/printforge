// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IdP` callback handling for `OIDC` and `SAML` flows.
//!
//! **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
//!
//! Processes the `IdP` redirect back to the enrollment portal after
//! user authentication. Validates CSRF state (`OIDC`) or `InResponseTo`
//! (`SAML`), exchanges codes for tokens, and extracts normalized claims.

use pf_auth::oidc::OidcFlowState;
use pf_user_provisioning::NormalizedClaims;
use serde::Deserialize;

use crate::error::EnrollmentError;

/// Parameters received at the `OIDC` callback endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcCallbackParams {
    /// Authorization code from the `IdP`.
    pub code: String,
    /// State parameter (must match the value sent in the redirect).
    pub state: String,
}

/// Parameters received at the `SAML` Assertion Consumer Service endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct SamlCallbackParams {
    /// Base64-encoded SAML response.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// Relay state (opaque value returned by the `IdP`).
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// The result of a successful `IdP` callback processing.
#[derive(Debug, Clone)]
pub struct CallbackResult {
    /// Normalized claims extracted from the `IdP` token or assertion.
    pub claims: NormalizedClaims,
}

/// Validate and process an `OIDC` callback.
///
/// Verifies the state parameter matches the stored flow state (CSRF
/// protection), then exchanges the authorization code for tokens.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `EnrollmentError::StateMismatch` if the state parameter does not match.
/// Returns `EnrollmentError::AuthenticationFailed` if the code exchange fails.
pub fn process_oidc_callback(
    params: &OidcCallbackParams,
    flow_state: &OidcFlowState,
) -> Result<CallbackResult, EnrollmentError> {
    // Validate CSRF state parameter.
    if params.state != flow_state.state {
        tracing::warn!("OIDC callback state mismatch — potential CSRF");
        return Err(EnrollmentError::StateMismatch);
    }

    // In a full implementation, this would:
    // 1. Exchange the authorization code for tokens via pf_auth::oidc::exchange_code
    // 2. Validate the ID token signature and claims
    // 3. Extract normalized claims via pf_user_provisioning::claims::normalize_oidc_claims
    //
    // For now, this returns an error indicating the token exchange is not yet wired up.
    tracing::info!("OIDC callback received, state validated");

    Err(EnrollmentError::AuthenticationFailed(
        "OIDC token exchange not yet implemented".to_string(),
    ))
}

/// Validate and process a `SAML` callback at the Assertion Consumer Service.
///
/// Validates the SAML response signature and `InResponseTo` attribute,
/// then extracts normalized claims from the assertion.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `EnrollmentError::InResponseToMismatch` if the `InResponseTo` does not
/// match the original `AuthnRequest` ID.
/// Returns `EnrollmentError::AuthenticationFailed` if assertion validation fails.
pub fn process_saml_callback(
    params: &SamlCallbackParams,
    expected_request_id: &str,
) -> Result<CallbackResult, EnrollmentError> {
    // Validate that we received a SAML response.
    if params.saml_response.is_empty() {
        return Err(EnrollmentError::MissingCallbackData {
            detail: "empty SAMLResponse".to_string(),
        });
    }

    // In a full implementation, this would:
    // 1. Base64-decode and parse the SAML response XML
    // 2. Validate the XML signature against the IdP certificate
    // 3. Check InResponseTo matches expected_request_id
    // 4. Extract attributes from the assertion
    // 5. Normalize claims via pf_user_provisioning::claims::normalize_saml_claims
    //
    // For now, this is a stub.
    let _ = expected_request_id;

    tracing::info!("SAML callback received");

    Err(EnrollmentError::AuthenticationFailed(
        "SAML response validation not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_flow_state() -> OidcFlowState {
        OidcFlowState {
            state: "test-state-123".to_string(),
            nonce: "test-nonce-456".to_string(),
            pkce_verifier: Some("test-verifier".to_string()),
            return_url: None,
        }
    }

    #[test]
    fn nist_ia8_oidc_state_mismatch_rejected() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: OIDC callback with mismatched state is rejected (CSRF protection).
        let flow_state = test_flow_state();
        let params = OidcCallbackParams {
            code: "auth-code-abc".to_string(),
            state: "wrong-state".to_string(),
        };

        let result = process_oidc_callback(&params, &flow_state);
        assert!(matches!(result, Err(EnrollmentError::StateMismatch)));
    }

    #[test]
    fn oidc_matching_state_proceeds() {
        // With matching state, the flow proceeds (returns stub error for now).
        let flow_state = test_flow_state();
        let params = OidcCallbackParams {
            code: "auth-code-abc".to_string(),
            state: "test-state-123".to_string(),
        };

        let result = process_oidc_callback(&params, &flow_state);
        // Currently returns AuthenticationFailed because exchange is not implemented.
        assert!(matches!(
            result,
            Err(EnrollmentError::AuthenticationFailed(_))
        ));
    }

    #[test]
    fn saml_empty_response_rejected() {
        let params = SamlCallbackParams {
            saml_response: String::new(),
            relay_state: None,
        };

        let result = process_saml_callback(&params, "_pf_request-id");
        assert!(matches!(
            result,
            Err(EnrollmentError::MissingCallbackData { .. })
        ));
    }

    #[test]
    fn saml_callback_with_response_proceeds() {
        let params = SamlCallbackParams {
            saml_response: "PHNhbWxwOlJlc3BvbnNlPjwvc2FtbHA6UmVzcG9uc2U+".to_string(),
            relay_state: Some("enroll".to_string()),
        };

        let result = process_saml_callback(&params, "_pf_request-id");
        // Currently returns AuthenticationFailed because parsing is not implemented.
        assert!(matches!(
            result,
            Err(EnrollmentError::AuthenticationFailed(_))
        ));
    }
}
