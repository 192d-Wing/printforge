// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Printer inventory CRUD types: model, serial, firmware, location, and status tracking.
//!
//! **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
//! Maintains a comprehensive inventory of all managed printers including
//! hardware details, firmware versions, network addresses, and physical locations.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};

use crate::discovery::{DiscoveryMethod, PrinterLocation};

/// A fully-registered printer in the fleet inventory.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
/// Contains all hardware, firmware, network, and location details required
/// for component inventory tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrinterRecord {
    /// Unique `PrintForge` printer identifier.
    pub id: PrinterId,

    /// Printer make and model.
    pub model: PrinterModel,

    /// Manufacturer serial number.
    pub serial_number: String,

    /// Current firmware version string.
    pub firmware_version: String,

    /// IP address of the printer on the management network.
    pub ip_address: IpAddr,

    /// Optional DNS hostname.
    pub hostname: Option<String>,

    /// Physical location within the installation.
    pub location: PrinterLocation,

    /// How this printer was originally discovered.
    pub discovery_method: DiscoveryMethod,

    /// Current operational status.
    pub status: PrinterStatus,

    /// Most recent supply levels.
    pub supply_levels: Option<SupplyLevel>,

    /// Current health score (0--100).
    pub health_score: Option<u8>,

    /// Lifetime total page count, if available.
    pub total_page_count: Option<u64>,

    /// When this printer was first added to inventory.
    pub registered_at: DateTime<Utc>,

    /// When this printer record was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the last successful poll occurred.
    pub last_polled_at: Option<DateTime<Utc>>,

    /// Count of consecutive failed polls.
    pub consecutive_poll_failures: u32,
}

/// Fields that may be updated on an existing printer record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrinterUpdate {
    /// Updated IP address.
    pub ip_address: Option<IpAddr>,
    /// Updated hostname.
    pub hostname: Option<Option<String>>,
    /// Updated firmware version.
    pub firmware_version: Option<String>,
    /// Updated physical location.
    pub location: Option<PrinterLocation>,
    /// Updated model information.
    pub model: Option<PrinterModel>,
}

/// Criteria for querying the printer inventory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrinterQuery {
    /// Filter by installation name (exact match).
    ///
    /// Mutually exclusive with [`Self::installations`] in practice — if both
    /// are set, repository implementations apply `installation` as an
    /// additional equality constraint.
    pub installation: Option<String>,
    /// Filter to printers whose installation is one of the given values.
    ///
    /// Empty vector means no installation-set constraint. Used for multi-site
    /// scope enforcement (e.g. a Site Admin authorized for multiple sites).
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    #[serde(default)]
    pub installations: Vec<String>,
    /// Filter by building.
    pub building: Option<String>,
    /// Filter by operational status.
    pub status: Option<PrinterStatus>,
    /// Filter by vendor name.
    pub vendor: Option<String>,
    /// Filter by model name (partial match).
    pub model: Option<String>,
    /// Filter printers with health score below this value.
    pub health_below: Option<u8>,
    /// Maximum number of results to return.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Counts of printers grouped by [`PrinterStatus`], scoped by installation.
///
/// Returned by [`PrinterRepository::count_by_status`] and
/// [`FleetService::status_summary`](crate::FleetService::status_summary) for
/// the dashboard fleet-overview widget. Fields correspond 1:1 to the variants
/// of [`PrinterStatus`].
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrinterStatusCounts {
    /// Printers reporting `Online`.
    pub online: u64,
    /// Printers reporting `Offline`.
    pub offline: u64,
    /// Printers reporting `Error`.
    pub error: u64,
    /// Printers reporting `Maintenance`.
    pub maintenance: u64,
    /// Printers reporting `Printing`.
    pub printing: u64,
}

/// Summary statistics for the fleet dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    /// Total number of managed printers.
    pub total_printers: u64,
    /// Number of printers currently online.
    pub online_count: u64,
    /// Number of printers currently offline.
    pub offline_count: u64,
    /// Number of printers in error state.
    pub error_count: u64,
    /// Number of printers in maintenance.
    pub maintenance_count: u64,
    /// Average health score across the fleet.
    pub average_health_score: f64,
    /// Number of printers with critical supply levels.
    pub critical_supply_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::fleet::PrinterId;

    #[test]
    fn nist_cm8_printer_record_tracks_required_fields() {
        // NIST CM-8: System Component Inventory requires tracking of
        // hardware, firmware, network, and location information.
        let record = PrinterRecord {
            id: PrinterId::new("PRN-0001").unwrap(),
            model: PrinterModel {
                vendor: "TestVendor".to_string(),
                model: "TestModel 9000".to_string(),
            },
            serial_number: "SN-TEST-001".to_string(),
            firmware_version: "1.0.0".to_string(),
            ip_address: "10.0.1.100".parse().unwrap(),
            hostname: Some("printer-0001.test.mil".to_string()),
            location: PrinterLocation {
                installation: "Test Base AFB".to_string(),
                building: "100".to_string(),
                floor: "1".to_string(),
                room: "101".to_string(),
            },
            discovery_method: DiscoveryMethod::SnmpV3Walk,
            status: PrinterStatus::Online,
            supply_levels: None,
            health_score: Some(95),
            total_page_count: Some(12345),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            last_polled_at: None,
            consecutive_poll_failures: 0,
        };

        // Verify all CM-8 required fields are present and non-empty.
        assert!(!record.serial_number.is_empty());
        assert!(!record.firmware_version.is_empty());
        assert!(!record.location.installation.is_empty());
        assert!(!record.model.vendor.is_empty());
    }

    #[test]
    fn printer_query_default_is_empty() {
        let query = PrinterQuery::default();
        assert!(query.installation.is_none());
        assert!(query.status.is_none());
        assert!(query.limit.is_none());
    }
}
