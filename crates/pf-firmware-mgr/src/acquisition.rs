// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Firmware acquisition: download from vendor feeds (`NIPR`) or import from
//! removable media (`SIPR` air-gap).
//!
//! **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
//! Ensures the fleet can receive firmware updates regardless of network enclave.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use pf_common::fleet::PrinterModel;

/// A firmware image acquired from a vendor source but not yet validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquiredFirmware {
    /// Unique identifier assigned at acquisition time.
    pub id: Uuid,

    /// Printer model this firmware targets.
    pub model: PrinterModel,

    /// Firmware version string from the vendor (e.g., `"4.11.2.1"`).
    pub version: String,

    /// SHA-256 hex digest as published by the vendor.
    pub expected_sha256: String,

    /// Raw firmware binary data.
    #[serde(skip)]
    pub data: Vec<u8>,

    /// How the firmware was obtained.
    pub source: AcquisitionSource,

    /// Timestamp of acquisition.
    pub acquired_at: DateTime<Utc>,
}

/// Describes how a firmware image was obtained.
///
/// On `NIPR`, firmware is downloaded directly from vendor feeds.
/// On `SIPR`, firmware is imported from removable media after manual
/// SHA-256 verification against vendor-published digests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AcquisitionSource {
    /// Downloaded from a vendor feed URL over the network.
    VendorFeed {
        /// The URL the firmware was downloaded from.
        url: Url,
    },

    /// Imported from removable media (air-gap / `SIPR` workflow).
    Media {
        /// Path to the media mount point or file on the import workstation.
        path: PathBuf,

        /// Operator who performed the import (for audit trail).
        imported_by: String,
    },
}

/// Metadata from a vendor firmware feed entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedEntry {
    /// Printer model this firmware targets.
    pub model: PrinterModel,

    /// Firmware version string.
    pub version: String,

    /// Download URL for the firmware binary.
    pub download_url: Url,

    /// SHA-256 hex digest published by the vendor.
    pub sha256: String,

    /// Release date from the vendor.
    pub release_date: DateTime<Utc>,

    /// Vendor release notes summary.
    pub release_notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquired_firmware_tracks_vendor_feed_source() {
        let fw = AcquiredFirmware {
            id: Uuid::new_v4(),
            model: PrinterModel {
                vendor: "HP".to_string(),
                model: "LaserJet Enterprise M612".to_string(),
            },
            version: "4.11.2.1".to_string(),
            expected_sha256: "abcdef1234567890".to_string(),
            data: vec![0x00, 0x01, 0x02],
            source: AcquisitionSource::VendorFeed {
                url: Url::parse("https://ftp.hp.com/firmware/m612_4.11.2.1.bin").unwrap(),
            },
            acquired_at: Utc::now(),
        };
        assert!(matches!(fw.source, AcquisitionSource::VendorFeed { .. }));
    }

    #[test]
    fn acquired_firmware_tracks_media_import_source() {
        let fw = AcquiredFirmware {
            id: Uuid::new_v4(),
            model: PrinterModel {
                vendor: "Xerox".to_string(),
                model: "VersaLink C405".to_string(),
            },
            version: "74.10.0".to_string(),
            expected_sha256: "deadbeef".to_string(),
            data: vec![0xFF],
            source: AcquisitionSource::Media {
                path: PathBuf::from("/mnt/usb/xerox_c405_74.10.0.bin"),
                imported_by: "DOE.JOHN.Q.1234567890".to_string(),
            },
            acquired_at: Utc::now(),
        };
        assert!(matches!(fw.source, AcquisitionSource::Media { .. }));
    }

    #[test]
    fn feed_entry_round_trips_json() {
        let entry = FeedEntry {
            model: PrinterModel {
                vendor: "Lexmark".to_string(),
                model: "MS826de".to_string(),
            },
            version: "MSXXX.081.232".to_string(),
            download_url: Url::parse("https://downloads.lexmark.com/fw/ms826de.fls").unwrap(),
            sha256: "aabbccdd".to_string(),
            release_date: Utc::now(),
            release_notes: Some("Security patch for CVE-2025-XXXX".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: FeedEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "MSXXX.081.232");
    }
}
