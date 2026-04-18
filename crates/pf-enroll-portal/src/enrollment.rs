// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Enrollment flow orchestrator.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-8 — System Use Notification
//!
//! Coordinates the complete enrollment flow:
//! 1. Detect enclave (`NIPR`/`SIPR`) from config
//! 2. Display `DoD` consent banner and require acknowledgment (AC-8)
//! 3. Redirect to `IdP` (`OIDC` or `SAML`)
//! 4. Process callback and extract claims
//! 5. JIT-provision or sync user via `pf-user-provisioning`

use pf_user_provisioning::NormalizedClaims;
use serde::{Deserialize, Serialize};

use crate::config::{Enclave, EnrollPortalConfig};
use crate::error::EnrollmentError;

/// Tracks the enrollment state machine for a single user session.
///
/// No user data is stored before successful `IdP` authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentSession {
    /// Current phase of the enrollment flow.
    pub phase: EnrollmentPhase,
    /// The enclave detected from configuration.
    pub enclave: Enclave,
    /// Banner nonce (set after banner is presented, before acknowledgment).
    pub banner_nonce: Option<String>,
    /// `OIDC` state parameter or `SAML` `AuthnRequest` ID (set after redirect).
    pub auth_request_id: Option<String>,
}

/// Phases of the enrollment flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentPhase {
    /// Initial state: banner not yet displayed.
    BannerPending,
    /// Banner has been displayed, awaiting user acknowledgment.
    BannerDisplayed,
    /// Banner acknowledged, redirecting to `IdP`.
    Redirecting,
    /// Callback received, processing authentication.
    Authenticating,
    /// Authentication succeeded, provisioning in progress.
    Provisioning,
    /// Enrollment complete, user is active.
    Complete,
    /// Enrollment failed.
    Failed,
}

/// Outcome of a completed enrollment flow.
#[derive(Debug, Clone)]
pub enum EnrollmentOutcome {
    /// A new user was created during enrollment.
    ///
    /// **NIST 800-53 Rev 5:** AC-2 — Account Management
    NewUser {
        /// The normalized claims from the `IdP`.
        claims: NormalizedClaims,
    },
    /// A returning user was recognized and attributes were synced.
    ReturningUser {
        /// The normalized claims from the `IdP`.
        claims: NormalizedClaims,
    },
}

/// Create a new enrollment session from the portal configuration.
///
/// Detects the enclave and initializes the session in the
/// [`EnrollmentPhase::BannerPending`] phase.
///
/// # Errors
///
/// Returns `EnrollmentError::EnclaveConfigInvalid` if the enclave
/// configuration is inconsistent (e.g., `NIPR` without `OIDC` config).
pub fn start_enrollment(config: &EnrollPortalConfig) -> Result<EnrollmentSession, EnrollmentError> {
    // Validate that the IdP config matches the enclave.
    match config.enclave {
        Enclave::Nipr => {
            if config.oidc.is_none() {
                return Err(EnrollmentError::EnclaveConfigInvalid(
                    "NIPR enclave requires OIDC configuration".to_string(),
                ));
            }
        }
        Enclave::Sipr => {
            if config.saml.is_none() {
                return Err(EnrollmentError::EnclaveConfigInvalid(
                    "SIPR enclave requires SAML configuration".to_string(),
                ));
            }
        }
    }

    tracing::info!(enclave = ?config.enclave, "enrollment session started");

    Ok(EnrollmentSession {
        phase: EnrollmentPhase::BannerPending,
        enclave: config.enclave,
        banner_nonce: None,
        auth_request_id: None,
    })
}

/// Advance the session to the [`EnrollmentPhase::BannerDisplayed`] phase.
///
/// Records the banner nonce so it can be validated upon acknowledgment.
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if the session is not in the
/// expected phase.
pub fn mark_banner_displayed(
    session: &mut EnrollmentSession,
    nonce: String,
) -> Result<(), EnrollmentError> {
    if session.phase != EnrollmentPhase::BannerPending {
        return Err(EnrollmentError::Internal(
            "unexpected phase for banner display".to_string(),
        ));
    }
    session.banner_nonce = Some(nonce);
    session.phase = EnrollmentPhase::BannerDisplayed;
    Ok(())
}

/// Advance the session to the [`EnrollmentPhase::Redirecting`] phase
/// after banner acknowledgment.
///
/// # Errors
///
/// Returns `EnrollmentError::BannerNotAcknowledged` if the session has not
/// been through the banner display phase.
pub fn mark_banner_acknowledged(session: &mut EnrollmentSession) -> Result<(), EnrollmentError> {
    if session.phase != EnrollmentPhase::BannerDisplayed {
        return Err(EnrollmentError::BannerNotAcknowledged);
    }
    session.phase = EnrollmentPhase::Redirecting;
    tracing::info!("banner acknowledged, proceeding to IdP redirect");
    Ok(())
}

/// Record the auth request identifier (state or `AuthnRequest` ID) and
/// advance to [`EnrollmentPhase::Authenticating`].
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if the session is not in the
/// redirecting phase.
pub fn mark_redirected(
    session: &mut EnrollmentSession,
    auth_request_id: String,
) -> Result<(), EnrollmentError> {
    if session.phase != EnrollmentPhase::Redirecting {
        return Err(EnrollmentError::Internal(
            "unexpected phase for redirect".to_string(),
        ));
    }
    session.auth_request_id = Some(auth_request_id);
    session.phase = EnrollmentPhase::Authenticating;
    Ok(())
}

/// Mark the enrollment as complete.
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if the session is not in the
/// provisioning or authenticating phase.
pub fn mark_complete(session: &mut EnrollmentSession) -> Result<(), EnrollmentError> {
    if session.phase != EnrollmentPhase::Provisioning
        && session.phase != EnrollmentPhase::Authenticating
    {
        return Err(EnrollmentError::Internal(
            "unexpected phase for completion".to_string(),
        ));
    }
    session.phase = EnrollmentPhase::Complete;
    tracing::info!("enrollment completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BannerConfig, DriverHubConfig, OidcEnrollConfig};
    use std::path::PathBuf;
    use url::Url;

    fn test_nipr_config() -> EnrollPortalConfig {
        EnrollPortalConfig {
            enclave: Enclave::Nipr,
            oidc: Some(OidcEnrollConfig {
                issuer_url: Url::parse("https://login.example.com/tenant1").unwrap(),
                client_id: "test-client".to_string(),
                redirect_uri: Url::parse("https://printforge.local/enroll/callback").unwrap(),
                scopes: vec!["openid".to_string()],
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

    #[test]
    fn nist_ac2_enrollment_starts_at_banner_pending() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Enrollment starts in BannerPending phase, ensuring
        // the consent banner is shown before any auth flow.
        let config = test_nipr_config();
        let session = start_enrollment(&config).unwrap();
        assert_eq!(session.phase, EnrollmentPhase::BannerPending);
        assert_eq!(session.enclave, Enclave::Nipr);
        assert!(session.banner_nonce.is_none());
        assert!(session.auth_request_id.is_none());
    }

    #[test]
    fn nist_ac8_banner_must_be_displayed_before_redirect() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Cannot proceed to redirect without banner acknowledgment.
        let config = test_nipr_config();
        let mut session = start_enrollment(&config).unwrap();

        // Attempting to acknowledge without displaying the banner fails.
        let result = mark_banner_acknowledged(&mut session);
        assert!(matches!(
            result,
            Err(EnrollmentError::BannerNotAcknowledged)
        ));
    }

    #[test]
    fn enrollment_phase_transitions_in_order() {
        let config = test_nipr_config();
        let mut session = start_enrollment(&config).unwrap();

        assert_eq!(session.phase, EnrollmentPhase::BannerPending);

        mark_banner_displayed(&mut session, "nonce-1".to_string()).unwrap();
        assert_eq!(session.phase, EnrollmentPhase::BannerDisplayed);

        mark_banner_acknowledged(&mut session).unwrap();
        assert_eq!(session.phase, EnrollmentPhase::Redirecting);

        mark_redirected(&mut session, "state-abc".to_string()).unwrap();
        assert_eq!(session.phase, EnrollmentPhase::Authenticating);

        mark_complete(&mut session).unwrap();
        assert_eq!(session.phase, EnrollmentPhase::Complete);
    }

    #[test]
    fn enrollment_rejects_invalid_enclave_config() {
        let mut config = test_nipr_config();
        config.oidc = None; // NIPR without OIDC

        let result = start_enrollment(&config);
        assert!(matches!(
            result,
            Err(EnrollmentError::EnclaveConfigInvalid(_))
        ));
    }

    #[test]
    fn mark_banner_displayed_records_nonce() {
        let config = test_nipr_config();
        let mut session = start_enrollment(&config).unwrap();

        mark_banner_displayed(&mut session, "my-nonce".to_string()).unwrap();
        assert_eq!(session.banner_nonce.as_deref(), Some("my-nonce"));
    }

    #[test]
    fn mark_redirected_records_auth_request_id() {
        let config = test_nipr_config();
        let mut session = start_enrollment(&config).unwrap();

        mark_banner_displayed(&mut session, "n".to_string()).unwrap();
        mark_banner_acknowledged(&mut session).unwrap();
        mark_redirected(&mut session, "state-xyz".to_string()).unwrap();

        assert_eq!(session.auth_request_id.as_deref(), Some("state-xyz"));
    }

    #[test]
    fn mark_complete_rejects_wrong_phase() {
        let config = test_nipr_config();
        let mut session = start_enrollment(&config).unwrap();

        // Still in BannerPending — cannot complete.
        let result = mark_complete(&mut session);
        assert!(matches!(result, Err(EnrollmentError::Internal(_))));
    }
}
