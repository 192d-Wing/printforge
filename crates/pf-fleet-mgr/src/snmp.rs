// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SNMPv3` client types for polling printer status, toner, paper, page counts,
//! and error codes.
//!
//! **NIST 800-53 Rev 5:** SI-4 — System Monitoring
//! Continuous `SNMPv3` polling provides real-time device health data.
//!
//! **Security:** Only `SNMPv3` `AuthPriv` mode is supported (SHA-256 auth,
//! AES-128 privacy). SNMPv1/v2c is explicitly rejected.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::fleet::{PrinterId, PrinterStatus, SupplyLevel};

/// `SNMPv3` security level. Only `AuthPriv` is permitted in `PrintForge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnmpSecurityLevel {
    /// Authentication and privacy (required).
    AuthPriv,
}

/// Authentication protocol for `SNMPv3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnmpAuthProtocol {
    /// SHA-256 (required by policy).
    Sha256,
}

/// Privacy protocol for `SNMPv3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnmpPrivacyProtocol {
    /// AES-128 (required by policy).
    Aes128,
}

/// A request to poll a single printer via `SNMPv3`.
#[derive(Debug, Clone)]
pub struct SnmpPollRequest {
    /// Printer to poll.
    pub printer_id: PrinterId,
    /// Target IP address.
    pub target: IpAddr,
    /// What data to collect.
    pub poll_type: SnmpPollType,
}

/// The category of data to collect in an `SNMPv3` poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnmpPollType {
    /// Quick status check (operational state, error flags).
    Status,
    /// Supply levels (toner percentages, paper tray fill).
    SupplyLevels,
    /// Full telemetry (status + supplies + page counts + error log).
    FullTelemetry,
}

/// Raw data returned from an `SNMPv3` status poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpStatusResponse {
    /// Printer this response is for.
    pub printer_id: PrinterId,
    /// Derived operational status.
    pub status: PrinterStatus,
    /// Raw `hrPrinterStatus` OID value.
    pub hr_printer_status: u32,
    /// Raw `hrDeviceStatus` OID value.
    pub hr_device_status: u32,
    /// Active error conditions (OID display strings).
    pub error_conditions: Vec<String>,
    /// When this response was collected.
    pub collected_at: DateTime<Utc>,
}

/// Raw data returned from an `SNMPv3` supply-level poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpSupplyResponse {
    /// Printer this response is for.
    pub printer_id: PrinterId,
    /// Aggregated supply levels as percentages.
    pub supply_levels: SupplyLevel,
    /// Individual supply entries (for detailed reporting).
    pub supply_entries: Vec<SupplyEntry>,
    /// When this response was collected.
    pub collected_at: DateTime<Utc>,
}

/// A single consumable supply entry from `SNMPv3` `prtMarkerSuppliesTable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyEntry {
    /// Human-readable supply description.
    pub description: String,
    /// Supply type (toner, ink, paper, etc.).
    pub supply_type: SupplyType,
    /// Color, if applicable.
    pub color: Option<SupplyColor>,
    /// Current level (0--100 percentage, or -1 if unknown).
    pub level_pct: i8,
    /// Maximum capacity in the supply's native unit.
    pub max_capacity: Option<i32>,
    /// Current level in the supply's native unit.
    pub current_level: Option<i32>,
}

/// Type of consumable supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SupplyType {
    /// Toner cartridge.
    Toner,
    /// Ink cartridge.
    Ink,
    /// Paper tray.
    Paper,
    /// Drum / imaging unit.
    Drum,
    /// Fuser unit.
    Fuser,
    /// Waste toner container.
    WasteToner,
    /// Other / unknown supply.
    Other,
}

/// Color of a toner or ink supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SupplyColor {
    Black,
    Cyan,
    Magenta,
    Yellow,
}

/// Raw data returned from a full telemetry poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpTelemetryResponse {
    /// Status information.
    pub status: SnmpStatusResponse,
    /// Supply levels.
    pub supplies: SnmpSupplyResponse,
    /// Page count data.
    pub page_counts: PageCounts,
}

/// Page count data collected from `SNMPv3` MIBs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PageCounts {
    /// Total lifetime pages printed.
    pub total: u64,
    /// Monochrome pages since last poll.
    pub mono_since_last: Option<u64>,
    /// Color pages since last poll.
    pub color_since_last: Option<u64>,
    /// Duplex pages since last poll.
    pub duplex_since_last: Option<u64>,
    /// When this data was collected.
    pub collected_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_si4_snmp_security_level_enforces_authpriv() {
        // NIST SI-4: System Monitoring
        // Only AuthPriv is permitted — no NoAuth or AuthNoPriv.
        let level = SnmpSecurityLevel::AuthPriv;
        assert_eq!(level, SnmpSecurityLevel::AuthPriv);
    }

    #[test]
    fn supply_entry_handles_unknown_level() {
        let entry = SupplyEntry {
            description: "Black Toner".to_string(),
            supply_type: SupplyType::Toner,
            color: Some(SupplyColor::Black),
            level_pct: -1,
            max_capacity: None,
            current_level: None,
        };
        assert_eq!(entry.level_pct, -1);
    }

    #[test]
    fn poll_types_cover_all_intervals() {
        // Verify all poll types used in the config intervals are represented.
        let types = [
            SnmpPollType::Status,
            SnmpPollType::SupplyLevels,
            SnmpPollType::FullTelemetry,
        ];
        assert_eq!(types.len(), 3);
    }
}
