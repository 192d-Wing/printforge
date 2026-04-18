// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for `pf-auth`.
//!
//! **Security:** Client-facing `Display` messages are intentionally vague
//! to prevent information leakage. Internal details are captured via
//! `#[source]` for structured logging only.

use thiserror::Error;

/// Errors returned by authentication and authorization operations.
///
/// All variants display a generic message to prevent leaking internal
/// details to API callers. Use the `#[source]` chain for diagnostics.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Certificate chain validation failed.
    ///
    /// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
    #[error("authentication failed")]
    ChainValidation(String),

    /// The certificate has been revoked (OCSP or CRL).
    ///
    /// **NIST 800-53 Rev 5:** IA-5(2), SC-17
    #[error("authentication failed")]
    CertificateRevoked(String),

    /// OCSP check could not be completed.
    #[error("authentication failed")]
    OcspCheckFailed(String),

    /// CRL check could not be completed.
    #[error("authentication failed")]
    CrlCheckFailed(String),

    /// The trust store could not be loaded or is empty (fail-closed).
    ///
    /// **NIST 800-53 Rev 5:** SC-12
    #[error("authentication failed")]
    TrustStoreUnavailable(String),

    /// EDIPI could not be extracted from the certificate Subject DN.
    #[error("authentication failed")]
    EdipiExtraction(String),

    /// OIDC flow error (token exchange, discovery, etc.).
    #[error("authentication failed")]
    OidcError(String),

    /// SAML assertion validation failure.
    #[error("authentication failed")]
    SamlError(String),

    /// JWT signing or validation failure.
    #[error("authentication failed")]
    JwtError(String),

    /// CAC PIN locked out after too many failed attempts.
    ///
    /// **NIST 800-53 Rev 5:** AC-7
    #[error("account locked")]
    PinLockout,

    /// CAC PIN validation failed (attempt counted).
    ///
    /// **NIST 800-53 Rev 5:** AC-7
    #[error("authentication failed")]
    PinInvalid {
        /// Number of attempts remaining before lockout.
        remaining_attempts: u32,
    },

    /// The request is missing required authentication credentials.
    #[error("authentication required")]
    MissingCredentials,

    /// The caller does not have the required role.
    ///
    /// **NIST 800-53 Rev 5:** AC-3
    #[error("access denied")]
    InsufficientRole,

    /// Token has expired.
    #[error("authentication failed")]
    TokenExpired,

    /// Configuration error prevented authentication from proceeding.
    #[error("authentication unavailable")]
    Configuration(String),

    /// Internal error (catch-all for unexpected failures).
    #[error("internal error")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_does_not_leak_chain_details() {
        let err = AuthError::ChainValidation("expired intermediate CA: CN=Test CA".into());
        let msg = format!("{err}");
        assert_eq!(msg, "authentication failed");
        assert!(!msg.contains("CN="));
        assert!(!msg.contains("expired"));
    }

    #[test]
    fn error_display_does_not_leak_oidc_details() {
        let err = AuthError::OidcError("invalid_grant: token revoked".into());
        let msg = format!("{err}");
        assert_eq!(msg, "authentication failed");
        assert!(!msg.contains("invalid_grant"));
    }

    #[test]
    fn pin_lockout_display_is_generic() {
        let msg = format!("{}", AuthError::PinLockout);
        assert_eq!(msg, "account locked");
    }

    #[test]
    fn insufficient_role_display() {
        let msg = format!("{}", AuthError::InsufficientRole);
        assert_eq!(msg, "access denied");
    }
}
