// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IdP` redirect construction for `OIDC` and `SAML` flows.
//!
//! **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
//!
//! Builds the authorization URL for `OIDC` (`NIPR` / `Entra ID`) or the
//! `SAML` `AuthnRequest` redirect URL for `SIPR` (DISA E-ICAM). The
//! `DoD` consent banner MUST be acknowledged before calling these functions.

use pf_auth::config::{OidcConfig, SamlConfig};
use pf_auth::oidc::{self, OidcFlowState};
use pf_auth::saml::{self, AuthnRequest};
use url::Url;

use crate::config::{Enclave, EnrollPortalConfig, OidcEnrollConfig, SamlEnrollConfig};
use crate::error::EnrollmentError;

/// Result of initiating an `IdP` redirect.
///
/// Contains the URL to redirect the user to, plus any server-side state
/// that must be persisted until the callback arrives.
#[derive(Debug)]
pub enum RedirectResult {
    /// `OIDC` redirect (used on `NIPR`).
    Oidc {
        /// The authorization URL to redirect the user to.
        redirect_url: Url,
        /// Server-side flow state (store in session).
        flow_state: OidcFlowState,
    },
    /// `SAML` redirect (used on `SIPR`).
    Saml {
        /// The `IdP` SSO URL with the `AuthnRequest`.
        redirect_url: Url,
        /// The `AuthnRequest` (store the ID for `InResponseTo` validation).
        authn_request: AuthnRequest,
    },
}

/// Initiate the `IdP` redirect based on the configured enclave.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// On `NIPR`, constructs an `OIDC` Authorization Code + PKCE URL.
/// On `SIPR`, constructs a `SAML` `AuthnRequest` redirect URL.
///
/// # Errors
///
/// Returns `EnrollmentError::EnclaveConfigInvalid` if the required `IdP`
/// configuration for the current enclave is missing.
/// Returns `EnrollmentError::AuthenticationFailed` if URL construction fails.
pub fn initiate_redirect(config: &EnrollPortalConfig) -> Result<RedirectResult, EnrollmentError> {
    match config.enclave {
        Enclave::Nipr => initiate_oidc_redirect(config.oidc.as_ref().ok_or_else(|| {
            EnrollmentError::EnclaveConfigInvalid(
                "OIDC config required for NIPR enclave".to_string(),
            )
        })?),
        Enclave::Sipr => initiate_saml_redirect(config.saml.as_ref().ok_or_else(|| {
            EnrollmentError::EnclaveConfigInvalid(
                "SAML config required for SIPR enclave".to_string(),
            )
        })?),
    }
}

/// Build an `OIDC` authorization URL with PKCE.
fn initiate_oidc_redirect(
    enroll_config: &OidcEnrollConfig,
) -> Result<RedirectResult, EnrollmentError> {
    let oidc_config = to_oidc_config(enroll_config);

    let (redirect_url, flow_state) = oidc::build_authorization_url(&oidc_config).map_err(|e| {
        tracing::error!("OIDC redirect construction failed: {e:?}");
        EnrollmentError::AuthenticationFailed(format!("OIDC redirect failed: {e}"))
    })?;

    tracing::info!("OIDC redirect URL constructed for enrollment");

    Ok(RedirectResult::Oidc {
        redirect_url,
        flow_state,
    })
}

/// Build a `SAML` `AuthnRequest` redirect URL.
fn initiate_saml_redirect(
    enroll_config: &SamlEnrollConfig,
) -> Result<RedirectResult, EnrollmentError> {
    let saml_config = to_saml_config(enroll_config);

    let authn_request = saml::build_authn_request(&saml_config, Some("enroll".to_string()))
        .map_err(|e| {
            tracing::error!("SAML AuthnRequest construction failed: {e:?}");
            EnrollmentError::AuthenticationFailed(format!("SAML redirect failed: {e}"))
        })?;

    let redirect_url = saml::build_redirect_url(&saml_config, &authn_request).map_err(|e| {
        tracing::error!("SAML redirect URL construction failed: {e:?}");
        EnrollmentError::AuthenticationFailed(format!("SAML redirect URL failed: {e}"))
    })?;

    tracing::info!("SAML redirect URL constructed for enrollment");

    Ok(RedirectResult::Saml {
        redirect_url,
        authn_request,
    })
}

/// Convert enrollment `OIDC` config to `pf-auth` `OidcConfig`.
fn to_oidc_config(enroll: &OidcEnrollConfig) -> OidcConfig {
    OidcConfig {
        issuer_url: enroll.issuer_url.clone(),
        client_id: enroll.client_id.clone(),
        redirect_uri: enroll.redirect_uri.clone(),
        scopes: enroll.scopes.clone(),
    }
}

/// Convert enrollment `SAML` config to `pf-auth` `SamlConfig`.
fn to_saml_config(enroll: &SamlEnrollConfig) -> SamlConfig {
    SamlConfig {
        idp_metadata_url: enroll.idp_metadata_url.clone(),
        sp_entity_id: enroll.sp_entity_id.clone(),
        acs_url: enroll.acs_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BannerConfig, DriverHubConfig};
    use std::path::PathBuf;

    fn test_nipr_config() -> EnrollPortalConfig {
        EnrollPortalConfig {
            enclave: Enclave::Nipr,
            oidc: Some(OidcEnrollConfig {
                issuer_url: Url::parse("https://login.example.com/tenant1").unwrap(),
                client_id: "test-client-id".to_string(),
                redirect_uri: Url::parse("https://printforge.local/enroll/callback").unwrap(),
                scopes: vec!["openid".to_string(), "profile".to_string()],
            }),
            saml: None,
            portal_base_url: Url::parse("https://printforge.local").unwrap(),
            driver_hub: DriverHubConfig {
                packages_dir: PathBuf::from("/opt/printforge/drivers"),
                download_base_url: Url::parse("https://printforge.local/drivers").unwrap(),
            },
            banner: BannerConfig::default(),
        }
    }

    fn test_sipr_config() -> EnrollPortalConfig {
        EnrollPortalConfig {
            enclave: Enclave::Sipr,
            oidc: None,
            saml: Some(SamlEnrollConfig {
                idp_metadata_url: Url::parse("https://idp.example.smil.mil/saml/sso").unwrap(),
                sp_entity_id: "https://printforge.local/saml/metadata".to_string(),
                acs_url: Url::parse("https://printforge.local/enroll/saml/acs").unwrap(),
            }),
            portal_base_url: Url::parse("https://printforge.local").unwrap(),
            driver_hub: DriverHubConfig {
                packages_dir: PathBuf::from("/opt/printforge/drivers"),
                download_base_url: Url::parse("https://printforge.local/drivers").unwrap(),
            },
            banner: BannerConfig::default(),
        }
    }

    #[test]
    fn nipr_redirect_produces_oidc_url() {
        let config = test_nipr_config();
        let result = initiate_redirect(&config).unwrap();

        match result {
            RedirectResult::Oidc {
                redirect_url,
                flow_state,
            } => {
                let url_str = redirect_url.to_string();
                assert!(url_str.contains("response_type=code"));
                assert!(url_str.contains("client_id=test-client-id"));
                assert!(url_str.contains("code_challenge"));
                assert!(!flow_state.state.is_empty());
            }
            RedirectResult::Saml { .. } => panic!("expected OIDC redirect for NIPR"),
        }
    }

    #[test]
    fn sipr_redirect_produces_saml_url() {
        let config = test_sipr_config();
        let result = initiate_redirect(&config).unwrap();

        match result {
            RedirectResult::Saml {
                redirect_url,
                authn_request,
            } => {
                let url_str = redirect_url.to_string();
                assert!(url_str.contains("SAMLRequest="));
                assert!(authn_request.id.starts_with("_pf_"));
            }
            RedirectResult::Oidc { .. } => panic!("expected SAML redirect for SIPR"),
        }
    }

    #[test]
    fn nipr_without_oidc_config_fails() {
        let mut config = test_nipr_config();
        config.oidc = None;

        let result = initiate_redirect(&config);
        assert!(matches!(
            result,
            Err(EnrollmentError::EnclaveConfigInvalid(_))
        ));
    }

    #[test]
    fn sipr_without_saml_config_fails() {
        let mut config = test_sipr_config();
        config.saml = None;

        let result = initiate_redirect(&config);
        assert!(matches!(
            result,
            Err(EnrollmentError::EnclaveConfigInvalid(_))
        ));
    }

    #[test]
    fn nist_ia8_oidc_redirect_has_csrf_state() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: OIDC redirect includes a state parameter for CSRF protection.
        let config = test_nipr_config();
        let result = initiate_redirect(&config).unwrap();

        if let RedirectResult::Oidc { flow_state, .. } = result {
            assert!(!flow_state.state.is_empty());
            assert!(!flow_state.nonce.is_empty());
        } else {
            panic!("expected OIDC result");
        }
    }

    #[test]
    fn nist_ia8_saml_redirect_has_unique_request_id() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: Each SAML AuthnRequest has a unique ID.
        let config = test_sipr_config();
        let r1 = initiate_redirect(&config).unwrap();
        let r2 = initiate_redirect(&config).unwrap();

        let id1 = match r1 {
            RedirectResult::Saml { authn_request, .. } => authn_request.id,
            RedirectResult::Oidc { .. } => panic!("expected SAML"),
        };
        let id2 = match r2 {
            RedirectResult::Saml { authn_request, .. } => authn_request.id,
            RedirectResult::Oidc { .. } => panic!("expected SAML"),
        };

        assert_ne!(id1, id2);
    }
}
