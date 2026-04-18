// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Identity types: EDIPI, Identity, Role, Principal.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation (EDIPI)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;

/// A validated 10-digit Electronic Data Interchange Personal Identifier.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
/// The constructor rejects any input that is not exactly 10 ASCII digits.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edipi(String);

impl Edipi {
    /// Create a new `Edipi` from raw input, validating that it is exactly
    /// 10 ASCII digits.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidEdipi` if the input is not 10 ASCII digits.
    pub fn new(raw: &str) -> Result<Self, ValidationError> {
        let trimmed = raw.trim();
        if trimmed.len() != 10 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(ValidationError::InvalidEdipi(raw.to_string()));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Return the inner value. Use sparingly — prefer passing `&Edipi`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `Display` redacts the EDIPI to prevent accidental PII leakage in logs.
impl fmt::Display for Edipi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***EDIPI***")
    }
}

/// `Debug` also redacts the EDIPI.
impl fmt::Debug for Edipi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Edipi").field(&"***EDIPI***").finish()
    }
}

/// Unique identifier for a DAF installation / site.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SiteId(pub String);

/// Authorization roles within `PrintForge`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Standard print user.
    User,
    /// Administrator for a specific installation.
    SiteAdmin(SiteId),
    /// Fleet-wide administrator across all installations.
    FleetAdmin,
    /// Read-only compliance auditor.
    Auditor,
}

/// A fully-authenticated identity extracted from a validated credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub edipi: Edipi,
    pub name: String,
    pub org: String,
    pub roles: Vec<Role>,
}

/// A principal is either a human user or a service account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Principal {
    /// An authenticated human user.
    User(Identity),
    /// A service-to-service identity (mTLS CN).
    Service { name: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_si10_edipi_accepts_valid_10_digits() {
        let edipi = Edipi::new("1234567890").unwrap();
        assert_eq!(edipi.as_str(), "1234567890");
    }

    #[test]
    fn nist_si10_edipi_rejects_non_numeric() {
        assert!(Edipi::new("12345ABCDE").is_err());
    }

    #[test]
    fn nist_si10_edipi_rejects_wrong_length() {
        assert!(Edipi::new("12345").is_err());
        assert!(Edipi::new("12345678901").is_err());
    }

    #[test]
    fn nist_si10_edipi_trims_whitespace() {
        let edipi = Edipi::new("  1234567890  ").unwrap();
        assert_eq!(edipi.as_str(), "1234567890");
    }

    #[test]
    fn edipi_display_is_redacted() {
        let edipi = Edipi::new("1234567890").unwrap();
        assert_eq!(format!("{edipi}"), "***EDIPI***");
    }

    #[test]
    fn edipi_debug_is_redacted() {
        let edipi = Edipi::new("1234567890").unwrap();
        let debug = format!("{edipi:?}");
        assert!(!debug.contains("1234567890"));
        assert!(debug.contains("***EDIPI***"));
    }
}
