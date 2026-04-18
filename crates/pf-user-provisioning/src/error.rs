// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for `pf-user-provisioning`.
//!
//! **Security:** Client-facing `Display` messages are intentionally vague
//! to prevent information leakage. Internal details are captured via
//! `#[source]` for structured logging only.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management

use thiserror::Error;

/// Errors returned by user provisioning operations.
///
/// All variants display a generic message to prevent leaking internal
/// details to API callers. Use the `#[source]` chain for diagnostics.
#[derive(Debug, Error)]
pub enum ProvisioningError {
    /// The EDIPI extracted from claims was invalid.
    ///
    /// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
    #[error("provisioning failed")]
    InvalidEdipi(#[source] pf_common::error::ValidationError),

    /// Required claims were missing from the identity token.
    #[error("provisioning failed")]
    MissingClaims {
        /// Which claim field was absent.
        field: String,
    },

    /// Claims normalization failed (e.g., unexpected format).
    #[error("provisioning failed")]
    ClaimsNormalization {
        /// Internal description for logging.
        detail: String,
    },

    /// No role mapping matched the user's `IdP` groups.
    #[error("provisioning failed")]
    NoRoleMapping {
        /// The `IdP` groups that had no matching rule.
        groups: Vec<String>,
    },

    /// The user record was not found in the repository.
    #[error("user not found")]
    UserNotFound {
        /// Internal identifier for logging (never exposed to caller).
        detail: String,
    },

    /// The user account is suspended and cannot be used.
    ///
    /// **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
    #[error("account suspended")]
    AccountSuspended,

    /// A repository (database) operation failed.
    #[error("provisioning failed")]
    Repository {
        /// Internal description for logging.
        detail: String,
    },

    /// An invalid cost center was provided in claims.
    #[error("provisioning failed")]
    InvalidCostCenter(#[source] pf_common::error::ValidationError),

    /// A configuration error prevented provisioning from proceeding.
    #[error("provisioning unavailable")]
    Configuration {
        /// Internal description for logging.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_does_not_leak_internal_details() {
        let err = ProvisioningError::MissingClaims {
            field: "edipi".to_string(),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "provisioning failed");
        assert!(!msg.contains("edipi"));
    }

    #[test]
    fn error_display_does_not_leak_repository_details() {
        let err = ProvisioningError::Repository {
            detail: "connection refused to pg:5432".to_string(),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "provisioning failed");
        assert!(!msg.contains("pg:5432"));
    }

    #[test]
    fn account_suspended_display() {
        let msg = format!("{}", ProvisioningError::AccountSuspended);
        assert_eq!(msg, "account suspended");
    }
}
