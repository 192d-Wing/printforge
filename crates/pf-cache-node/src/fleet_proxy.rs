// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet proxy for direct SNMP/IPPS connections to local printers.
//!
//! During `DDIL` mode, the fleet proxy continues to communicate directly
//! with printers at this installation via `SNMPv3` and IPPS, independent
//! of the central fleet manager.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality (IPPS)

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use pf_common::fleet::{PrinterId, PrinterStatus, SupplyLevel};
use serde::{Deserialize, Serialize};

/// A printer known to this installation's fleet proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalPrinter {
    /// The printer's unique identifier.
    pub id: PrinterId,
    /// IP address of the printer on the local network.
    pub ip_addr: IpAddr,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Current supply levels.
    pub supplies: Option<SupplyLevel>,
    /// When the printer was last polled.
    pub last_polled: Option<DateTime<Utc>>,
    /// Whether the printer supports IPPS.
    pub ipps_capable: bool,
}

/// Summary statistics for the local printer fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProxySummary {
    /// Total number of known printers.
    pub total_printers: u32,
    /// Number of printers currently online.
    pub online_printers: u32,
    /// Number of printers in error state.
    pub error_printers: u32,
    /// Number of printers with low supply levels.
    pub low_supply_printers: u32,
    /// Timestamp of the last full poll cycle.
    pub last_poll_cycle: Option<DateTime<Utc>>,
}

/// Threshold below which a supply level is considered low.
const LOW_SUPPLY_THRESHOLD: u8 = 10;

/// Manages direct communication with local printers.
///
/// **NIST 800-53 Rev 5:** SC-8 — uses IPPS for secure communication
/// with printers that support it.
#[derive(Debug)]
pub struct FleetProxy {
    /// Known printers indexed by their ID.
    printers: HashMap<String, LocalPrinter>,
    /// Polling interval for status updates.
    poll_interval: Duration,
}

impl FleetProxy {
    /// Create a new `FleetProxy` with the given polling interval.
    #[must_use]
    pub fn new(poll_interval: Duration) -> Self {
        Self {
            printers: HashMap::new(),
            poll_interval,
        }
    }

    /// Return the configured poll interval.
    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Return the number of known printers.
    #[must_use]
    pub fn printer_count(&self) -> usize {
        self.printers.len()
    }

    /// Register a local printer with the fleet proxy.
    pub fn register_printer(&mut self, printer: LocalPrinter) {
        tracing::info!(
            printer_id = %printer.id.as_str(),
            ip = %printer.ip_addr,
            "registered local printer"
        );
        self.printers
            .insert(printer.id.as_str().to_string(), printer);
    }

    /// Remove a printer from the fleet proxy.
    pub fn deregister_printer(&mut self, printer_id: &PrinterId) {
        tracing::info!(
            printer_id = %printer_id.as_str(),
            "deregistered local printer"
        );
        self.printers.remove(printer_id.as_str());
    }

    /// Look up a printer by its ID.
    #[must_use]
    pub fn get_printer(&self, printer_id: &PrinterId) -> Option<&LocalPrinter> {
        self.printers.get(printer_id.as_str())
    }

    /// Update the status and supplies for a printer after polling.
    pub fn update_printer_status(
        &mut self,
        printer_id: &PrinterId,
        status: PrinterStatus,
        supplies: Option<SupplyLevel>,
    ) {
        if let Some(printer) = self.printers.get_mut(printer_id.as_str()) {
            printer.status = status;
            printer.supplies = supplies;
            printer.last_polled = Some(Utc::now());
            tracing::debug!(
                printer_id = %printer_id.as_str(),
                status = ?status,
                "updated printer status"
            );
        }
    }

    /// Generate a summary of the local fleet status.
    #[must_use]
    pub fn summary(&self) -> FleetProxySummary {
        #[allow(clippy::cast_possible_truncation)]
        let total_printers = self.printers.len() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let online_printers = self
            .printers
            .values()
            .filter(|p| p.status == PrinterStatus::Online || p.status == PrinterStatus::Printing)
            .count() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let error_printers = self
            .printers
            .values()
            .filter(|p| p.status == PrinterStatus::Error)
            .count() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let low_supply_printers = self
            .printers
            .values()
            .filter(|p| {
                p.supplies.is_some_and(|s| {
                    s.toner_k < LOW_SUPPLY_THRESHOLD || s.paper < LOW_SUPPLY_THRESHOLD
                })
            })
            .count() as u32;
        let last_poll_cycle = self.printers.values().filter_map(|p| p.last_polled).min();

        FleetProxySummary {
            total_printers,
            online_printers,
            error_printers,
            low_supply_printers,
            last_poll_cycle,
        }
    }

    /// Return all printers with a given status.
    #[must_use]
    pub fn printers_with_status(&self, status: PrinterStatus) -> Vec<&LocalPrinter> {
        self.printers
            .values()
            .filter(|p| p.status == status)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn test_printer(id: &str, status: PrinterStatus) -> LocalPrinter {
        LocalPrinter {
            id: PrinterId::new(id).unwrap(),
            ip_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            status,
            supplies: Some(SupplyLevel {
                toner_k: 50,
                toner_c: 50,
                toner_m: 50,
                toner_y: 50,
                paper: 80,
            }),
            last_polled: None,
            ipps_capable: true,
        }
    }

    #[test]
    fn register_and_lookup_printer() {
        let mut proxy = FleetProxy::new(Duration::from_secs(60));
        let printer = test_printer("PRN-0001", PrinterStatus::Online);
        let id = printer.id.clone();
        proxy.register_printer(printer);
        assert_eq!(proxy.printer_count(), 1);
        assert!(proxy.get_printer(&id).is_some());
    }

    #[test]
    fn deregister_printer_removes_it() {
        let mut proxy = FleetProxy::new(Duration::from_secs(60));
        let printer = test_printer("PRN-0001", PrinterStatus::Online);
        let id = printer.id.clone();
        proxy.register_printer(printer);
        proxy.deregister_printer(&id);
        assert_eq!(proxy.printer_count(), 0);
    }

    #[test]
    fn update_printer_status() {
        let mut proxy = FleetProxy::new(Duration::from_secs(60));
        let printer = test_printer("PRN-0001", PrinterStatus::Online);
        let id = printer.id.clone();
        proxy.register_printer(printer);
        proxy.update_printer_status(&id, PrinterStatus::Error, None);
        let updated = proxy.get_printer(&id).unwrap();
        assert_eq!(updated.status, PrinterStatus::Error);
        assert!(updated.last_polled.is_some());
    }

    #[test]
    fn summary_counts_correctly() {
        let mut proxy = FleetProxy::new(Duration::from_secs(60));
        proxy.register_printer(test_printer("PRN-0001", PrinterStatus::Online));
        proxy.register_printer(test_printer("PRN-0002", PrinterStatus::Error));
        proxy.register_printer(test_printer("PRN-0003", PrinterStatus::Offline));
        let summary = proxy.summary();
        assert_eq!(summary.total_printers, 3);
        assert_eq!(summary.online_printers, 1);
        assert_eq!(summary.error_printers, 1);
    }

    #[test]
    fn low_supply_detection() {
        let mut proxy = FleetProxy::new(Duration::from_secs(60));
        let mut printer = test_printer("PRN-0001", PrinterStatus::Online);
        printer.supplies = Some(SupplyLevel {
            toner_k: 5, // below threshold
            toner_c: 50,
            toner_m: 50,
            toner_y: 50,
            paper: 80,
        });
        proxy.register_printer(printer);
        let summary = proxy.summary();
        assert_eq!(summary.low_supply_printers, 1);
    }

    #[test]
    fn printers_with_status_filters() {
        let mut proxy = FleetProxy::new(Duration::from_secs(60));
        proxy.register_printer(test_printer("PRN-0001", PrinterStatus::Online));
        proxy.register_printer(test_printer("PRN-0002", PrinterStatus::Online));
        proxy.register_printer(test_printer("PRN-0003", PrinterStatus::Offline));
        let online = proxy.printers_with_status(PrinterStatus::Online);
        assert_eq!(online.len(), 2);
    }
}
