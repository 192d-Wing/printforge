// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for `pf-enroll-portal`.
//!
//! **Security:** Client-facing `Display` messages are intentionally vague
//! to prevent information leakage. Internal details are captured via
//! `#[source]` for structured logging only.

use thiserror::Error;

/// Errors returned by enrollment portal operations.
///
/// All variants display a generic message to prevent leaking internal
/// details to API callers. Use the `#[source]` chain for diagnostics.
#[derive(Debug, Error)]
pub enum EnrollmentError {
    /// The user has not acknowledged the `DoD` consent banner.
    ///
    /// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
    #[error("consent banner acknowledgment required")]
    BannerNotAcknowledged,

    /// The `OIDC` state parameter did not match (CSRF protection).
    #[error("authentication failed")]
    StateMismatch,

    /// The `SAML` `InResponseTo` did not match the original `AuthnRequest` ID.
    #[error("authentication failed")]
    InResponseToMismatch,

    /// The `IdP` callback did not include an authorization code or assertion.
    #[error("authentication failed")]
    MissingCallbackData {
        /// Internal detail describing which callback data was missing.
        detail: String,
    },

    /// Authentication via the `IdP` failed.
    #[error("authentication failed")]
    AuthenticationFailed(String),

    /// JIT provisioning or attribute sync failed.
    ///
    /// **NIST 800-53 Rev 5:** AC-2 — Account Management
    #[error("enrollment failed")]
    ProvisioningFailed(String),

    /// The requested driver package was not found.
    #[error("driver package not found")]
    DriverNotFound {
        /// Operating system requested.
        os: String,
        /// Architecture requested.
        arch: String,
    },

    /// Enclave configuration is missing or invalid.
    #[error("service unavailable")]
    EnclaveConfigInvalid(String),

    /// Rate limit exceeded on enrollment attempts.
    #[error("too many requests")]
    RateLimitExceeded,

    /// Profile update validation failed.
    #[error("invalid profile data")]
    InvalidProfile {
        /// Description of the validation failure.
        detail: String,
    },

    /// Internal error (catch-all for unexpected failures).
    #[error("internal error")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_does_not_leak_internal_details() {
        let err =
            EnrollmentError::AuthenticationFailed("OIDC token exchange: invalid_grant".to_string());
        let msg = format!("{err}");
        assert_eq!(msg, "authentication failed");
        assert!(!msg.contains("invalid_grant"));
    }

    #[test]
    fn error_display_does_not_leak_provisioning_details() {
        let err = EnrollmentError::ProvisioningFailed(
            "database connection refused: 10.0.0.5:5432".to_string(),
        );
        let msg = format!("{err}");
        assert_eq!(msg, "enrollment failed");
        assert!(!msg.contains("10.0.0.5"));
    }

    #[test]
    fn nist_ac8_banner_error_is_descriptive() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: The banner acknowledgment error clearly states the requirement.
        let err = EnrollmentError::BannerNotAcknowledged;
        let msg = format!("{err}");
        assert!(msg.contains("consent banner"));
    }

    #[test]
    fn state_mismatch_does_not_leak_state_values() {
        let err = EnrollmentError::StateMismatch;
        let msg = format!("{err}");
        assert_eq!(msg, "authentication failed");
    }
}
