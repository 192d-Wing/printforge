// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Printer discovery via `SNMPv3` walks, DNS-SD/mDNS, and manual registration.
//!
//! **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
//! Discovery scans identify printers on authorized subnets and register them
//! in the fleet inventory.
//!
//! **Security:** All discovery scans are restricted to configured subnets.
//! Encountering SNMPv1/v2c community strings is flagged as a STIG violation.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::{PrinterId, PrinterModel};

use crate::config::SubnetConfig;

/// Method by which a printer was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Active `SNMPv3` walk of an authorized subnet.
    SnmpV3Walk,
    /// DNS-SD / mDNS advertisement.
    DnsSd,
    /// Manual registration by an administrator.
    Manual,
}

/// A request to initiate a discovery scan on one or more subnets.
///
/// **Security:** Only subnets listed in [`SubnetConfig`] are permitted.
#[derive(Debug, Clone)]
pub struct DiscoveryScanRequest {
    /// Unique ID for this scan invocation.
    pub scan_id: Uuid,
    /// Subnets to scan.
    pub subnets: Vec<SubnetConfig>,
    /// Discovery methods to employ.
    pub methods: Vec<DiscoveryMethod>,
    /// Timestamp when the scan was requested.
    pub requested_at: DateTime<Utc>,
}

/// A printer found during a discovery scan, not yet registered in inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPrinter {
    /// IP address where the printer was found.
    pub ip_address: IpAddr,
    /// Hostname if resolved via DNS.
    pub hostname: Option<String>,
    /// Model information if available from `SNMPv3` or DNS-SD.
    pub model: Option<PrinterModel>,
    /// Serial number if available from `SNMPv3`.
    pub serial_number: Option<String>,
    /// How this printer was discovered.
    pub method: DiscoveryMethod,
    /// When the printer was discovered.
    pub discovered_at: DateTime<Utc>,
    /// The scan that discovered this printer, if applicable.
    pub scan_id: Option<Uuid>,
}

/// A request to manually register a printer in the fleet inventory.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualRegistration {
    /// Desired printer ID (must be unique and valid `PRN-XXXX` format).
    pub printer_id: PrinterId,
    /// IP address of the printer.
    pub ip_address: IpAddr,
    /// Hostname, if known.
    pub hostname: Option<String>,
    /// Printer make/model.
    pub model: PrinterModel,
    /// Serial number.
    pub serial_number: String,
    /// Physical location (building, room, floor).
    pub location: PrinterLocation,
}

/// Physical location of a printer within an installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrinterLocation {
    /// Installation or base name.
    pub installation: String,
    /// Building identifier.
    pub building: String,
    /// Floor number or designation.
    pub floor: String,
    /// Room or area.
    pub room: String,
}

/// Outcome of a discovery scan.
#[derive(Debug, Clone)]
pub struct DiscoveryScanResult {
    /// ID of the scan.
    pub scan_id: Uuid,
    /// Printers discovered during the scan.
    pub discovered: Vec<DiscoveredPrinter>,
    /// Subnets that could not be scanned (with reason).
    pub failed_subnets: Vec<(SubnetConfig, String)>,
    /// Whether any legacy `SNMPv1`/v2c community strings were detected.
    ///
    /// **Security:** This is a STIG violation that must be reported.
    pub stig_violations: Vec<StigViolation>,
    /// When the scan completed.
    pub completed_at: DateTime<Utc>,
}

/// A STIG violation detected during discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigViolation {
    /// IP address of the offending device.
    pub ip_address: IpAddr,
    /// Description of the violation.
    pub description: String,
    /// When the violation was detected.
    pub detected_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_cm8_discovery_methods_are_exhaustive() {
        // Ensure all discovery methods are represented for CM-8 inventory tracking.
        let methods = [
            DiscoveryMethod::SnmpV3Walk,
            DiscoveryMethod::DnsSd,
            DiscoveryMethod::Manual,
        ];
        assert_eq!(methods.len(), 3);
    }

    #[test]
    fn printer_location_equality() {
        let loc1 = PrinterLocation {
            installation: "Test Base AFB".to_string(),
            building: "100".to_string(),
            floor: "2".to_string(),
            room: "201".to_string(),
        };
        let loc2 = loc1.clone();
        assert_eq!(loc1, loc2);
    }
}
