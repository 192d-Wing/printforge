// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet service trait defining the high-level API for fleet management.
//!
//! The `FleetService` trait provides a business-logic layer above the raw
//! repository, returning view types (`PrinterSummary`, `PrinterDetail`,
//! `PrinterStatusInfo`) suitable for API responses.
//!
//! **NIST 800-53 Rev 5:** CM-8 — System Component Inventory

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};

use crate::discovery::PrinterLocation;
use crate::error::FleetError;
use crate::health::HealthScore;
use crate::inventory::PrinterQuery;

/// A concise printer summary for list views and dashboards.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrinterSummary {
    /// Unique printer identifier.
    pub id: PrinterId,
    /// Printer make and model.
    pub model: PrinterModel,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Physical location within the installation.
    pub location: PrinterLocation,
    /// Current health score (0--100), if available.
    pub health_score: Option<u8>,
    /// When the printer record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Full printer detail for the single-printer view.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrinterDetail {
    /// Unique printer identifier.
    pub id: PrinterId,
    /// Printer make and model.
    pub model: PrinterModel,
    /// Manufacturer serial number.
    pub serial_number: String,
    /// Current firmware version string.
    pub firmware_version: String,
    /// IP address on the management network.
    pub ip_address: IpAddr,
    /// Optional DNS hostname.
    pub hostname: Option<String>,
    /// Physical location within the installation.
    pub location: PrinterLocation,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Current supply levels.
    pub supply_levels: Option<SupplyLevel>,
    /// Current health score (0--100).
    pub health_score: Option<u8>,
    /// Lifetime total page count.
    pub total_page_count: Option<u64>,
    /// When this printer was first added to inventory.
    pub registered_at: DateTime<Utc>,
    /// When this printer record was last updated.
    pub updated_at: DateTime<Utc>,
    /// When the last successful poll occurred.
    pub last_polled_at: Option<DateTime<Utc>>,
}

/// Printer status information including supply levels and health score.
///
/// **NIST 800-53 Rev 5:** SI-4 — System Monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrinterStatusInfo {
    /// Unique printer identifier.
    pub id: PrinterId,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Current supply levels, if available.
    pub supply_levels: Option<SupplyLevel>,
    /// Current health score with breakdown.
    pub health_score: Option<HealthScore>,
    /// When the last successful poll occurred.
    pub last_polled_at: Option<DateTime<Utc>>,
    /// Count of consecutive poll failures.
    pub consecutive_poll_failures: u32,
}

/// High-level fleet management service trait.
///
/// Provides business-logic operations on top of the raw [`PrinterRepository`].
/// Implementations handle mapping between persistence types and API view types.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
#[allow(clippy::type_complexity)]
pub trait FleetService: Send + Sync {
    /// List printers with filtering and pagination.
    ///
    /// Returns a tuple of `(results, total_count)` where `total_count` is the
    /// total number of matching records (before pagination) for UI paging.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::Repository`] on persistence failure.
    fn list_printers(
        &self,
        filter: PrinterQuery,
        limit: u32,
        offset: u32,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<PrinterSummary>, u64), FleetError>> + Send + '_>>;

    /// Retrieve full detail for a single printer.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::PrinterNotFound`] if the printer does not exist.
    /// Returns [`FleetError::Repository`] on persistence failure.
    fn get_printer(
        &self,
        id: PrinterId,
    ) -> Pin<Box<dyn Future<Output = Result<PrinterDetail, FleetError>> + Send + '_>>;

    /// Retrieve current status and supply levels for a printer.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::PrinterNotFound`] if the printer does not exist.
    /// Returns [`FleetError::Repository`] on persistence failure.
    fn get_printer_status(
        &self,
        id: PrinterId,
    ) -> Pin<Box<dyn Future<Output = Result<PrinterStatusInfo, FleetError>> + Send + '_>>;
}
