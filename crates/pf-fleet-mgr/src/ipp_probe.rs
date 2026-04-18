// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! IPP Get-Printer-Attributes probe types for capability discovery.
//!
//! Uses IPP/IPPS `Get-Printer-Attributes` to discover printer capabilities
//! (supported media sizes, color modes, finishing options, etc.) that cannot
//! be obtained via `SNMPv3` alone.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use pf_common::fleet::PrinterId;

/// A request to probe a printer via IPP `Get-Printer-Attributes`.
#[derive(Debug, Clone)]
pub struct IppProbeRequest {
    /// Printer to probe.
    pub printer_id: PrinterId,
    /// IPPS endpoint URL (e.g., `ipps://10.0.1.100:631/ipp/print`).
    pub endpoint: Url,
}

/// Capabilities discovered via IPP `Get-Printer-Attributes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IppCapabilities {
    /// Printer this capability set belongs to.
    pub printer_id: PrinterId,
    /// IPP printer name attribute.
    pub printer_name: String,
    /// IPP printer-info attribute.
    pub printer_info: Option<String>,
    /// IPP printer-make-and-model attribute.
    pub make_and_model: Option<String>,
    /// Supported document formats (MIME types).
    pub document_formats: Vec<String>,
    /// Whether color printing is supported.
    pub color_supported: bool,
    /// Whether duplex (two-sided) printing is supported.
    pub duplex_supported: bool,
    /// Supported media sizes (e.g., `iso_a4_210x297mm`, `na_letter_8.5x11in`).
    pub media_supported: Vec<String>,
    /// Supported finishing options (staple, punch, fold, etc.).
    pub finishing_supported: Vec<FinishingOption>,
    /// IPP version(s) supported by the printer.
    pub ipp_versions: Vec<String>,
    /// When this probe was performed.
    pub probed_at: DateTime<Utc>,
}

/// Finishing options reported by a printer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FinishingOption {
    /// No finishing.
    None,
    /// Staple.
    Staple,
    /// Hole punch.
    Punch,
    /// Fold.
    Fold,
    /// Booklet.
    Booklet,
    /// Trim / cut.
    Trim,
}

/// Result of an IPP probe attempt.
#[derive(Debug, Clone)]
pub enum IppProbeResult {
    /// Successfully retrieved capabilities.
    Success(IppCapabilities),
    /// Printer responded but returned an IPP error status code.
    IppError {
        /// Printer that was probed.
        printer_id: PrinterId,
        /// IPP status code.
        status_code: u16,
        /// Human-readable status message, if available.
        status_message: Option<String>,
    },
    /// Connection or transport-level failure.
    ConnectionFailed {
        /// Printer that was probed.
        printer_id: PrinterId,
        /// Error description (sanitized for logging — no secrets).
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipp_capabilities_tracks_essential_attributes() {
        let caps = IppCapabilities {
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            printer_name: "Test Printer".to_string(),
            printer_info: Some("Floor 2 Hallway".to_string()),
            make_and_model: Some("TestVendor TestModel".to_string()),
            document_formats: vec![
                "application/pdf".to_string(),
                "application/postscript".to_string(),
            ],
            color_supported: true,
            duplex_supported: true,
            media_supported: vec![
                "na_letter_8.5x11in".to_string(),
                "iso_a4_210x297mm".to_string(),
            ],
            finishing_supported: vec![FinishingOption::Staple, FinishingOption::Punch],
            ipp_versions: vec!["2.0".to_string()],
            probed_at: Utc::now(),
        };

        assert!(caps.color_supported);
        assert!(caps.duplex_supported);
        assert_eq!(caps.document_formats.len(), 2);
    }

    #[test]
    fn ipp_probe_result_variants() {
        let printer_id = PrinterId::new("PRN-0001").unwrap();

        // Verify all result variants can be constructed.
        let _error = IppProbeResult::IppError {
            printer_id: printer_id.clone(),
            status_code: 0x0500,
            status_message: Some("server-error-internal-error".to_string()),
        };

        let _failed = IppProbeResult::ConnectionFailed {
            printer_id,
            reason: "connection timed out".to_string(),
        };
    }
}
