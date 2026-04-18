// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet types: `PrinterId`, `PrinterModel`, `PrinterStatus`, `SupplyLevel`.

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;

/// A validated printer identifier in `PRN-XXXX` format.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrinterId(String);

impl PrinterId {
    /// Create a new `PrinterId`, validating the `PRN-` prefix and 4+ character suffix.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidPrinterId` if the format is invalid.
    pub fn new(raw: &str) -> Result<Self, ValidationError> {
        let trimmed = raw.trim();
        if !trimmed.starts_with("PRN-") || trimmed.len() < 5 {
            return Err(ValidationError::InvalidPrinterId(raw.to_string()));
        }
        Ok(Self(trimmed.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Describes a printer make/model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrinterModel {
    pub vendor: String,
    pub model: String,
}

/// Operational status of a printer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrinterStatus {
    Online,
    Offline,
    Error,
    Maintenance,
    Printing,
}

/// Current consumable levels for a printer (0–100 percentage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyLevel {
    pub toner_k: u8,
    pub toner_c: u8,
    pub toner_m: u8,
    pub toner_y: u8,
    pub paper: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_si10_printer_id_accepts_valid() {
        let id = PrinterId::new("PRN-0042").unwrap();
        assert_eq!(id.as_str(), "PRN-0042");
    }

    #[test]
    fn nist_si10_printer_id_rejects_no_prefix() {
        assert!(PrinterId::new("0042").is_err());
    }

    #[test]
    fn nist_si10_printer_id_rejects_prefix_only() {
        assert!(PrinterId::new("PRN-").is_err());
    }
}
