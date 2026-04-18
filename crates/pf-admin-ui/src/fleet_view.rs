// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet overview types for the admin dashboard: printers by site, status,
//! model, with search and filter support.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All fleet queries are scoped by
//! the requester's [`DataScope`](crate::scope::DataScope).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};
use pf_common::identity::SiteId;

/// A printer summary row as displayed in the fleet overview table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPrinterSummary {
    /// Unique printer identifier.
    pub printer_id: PrinterId,

    /// Human-readable display name.
    pub display_name: String,

    /// Site where the printer is located.
    pub site_id: SiteId,

    /// Building / room location string.
    pub location: String,

    /// Make and model.
    pub model: PrinterModel,

    /// Current operational status.
    pub status: PrinterStatus,

    /// Current consumable levels.
    pub supply_levels: SupplyLevel,

    /// Last time the printer reported status via `SNMPv3`.
    pub last_seen: DateTime<Utc>,

    /// Health score (0.0 = critical, 1.0 = healthy).
    pub health_score: f64,
}

/// Filters for the fleet overview query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetFilter {
    /// Filter by site.
    pub site_id: Option<SiteId>,

    /// Filter by operational status.
    pub status: Option<PrinterStatus>,

    /// Filter by vendor name (case-insensitive partial match).
    pub vendor: Option<String>,

    /// Filter by model name (case-insensitive partial match).
    pub model: Option<String>,

    /// Free-text search across display name, location, and printer ID.
    pub search: Option<String>,

    /// Only show printers with health score below this threshold.
    pub health_below: Option<f64>,
}

/// Sort options for the fleet overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FleetSortField {
    /// Sort by display name.
    DisplayName,
    /// Sort by site.
    Site,
    /// Sort by status.
    Status,
    /// Sort by health score.
    HealthScore,
    /// Sort by last seen timestamp.
    LastSeen,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortDirection {
    /// Ascending order.
    #[default]
    Asc,
    /// Descending order.
    Desc,
}

/// Paginated fleet overview request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetViewRequest {
    /// Filters to apply.
    pub filter: FleetFilter,

    /// Field to sort by.
    pub sort_by: Option<FleetSortField>,

    /// Sort direction.
    pub sort_dir: SortDirection,

    /// Page number (1-based).
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

/// Paginated fleet overview response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetViewResponse {
    /// Printer summaries for the current page.
    pub printers: Vec<FleetPrinterSummary>,

    /// Total number of printers matching the filter (for pagination).
    pub total_count: u64,

    /// Current page number.
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

/// Aggregated fleet statistics by status, for dashboard pie/bar charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStatusSummary {
    /// Number of printers online.
    pub online: u64,
    /// Number of printers offline.
    pub offline: u64,
    /// Number of printers in error state.
    pub error: u64,
    /// Number of printers in maintenance.
    pub maintenance: u64,
    /// Number of printers currently printing.
    pub printing: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_filter_default_is_unfiltered() {
        let filter = FleetFilter::default();
        assert!(filter.site_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.vendor.is_none());
        assert!(filter.model.is_none());
        assert!(filter.search.is_none());
        assert!(filter.health_below.is_none());
    }

    #[test]
    fn sort_direction_default_is_ascending() {
        assert_eq!(SortDirection::default(), SortDirection::Asc);
    }

    #[test]
    fn fleet_status_summary_serialization() {
        let summary = FleetStatusSummary {
            online: 30,
            offline: 5,
            error: 2,
            maintenance: 3,
            printing: 10,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: FleetStatusSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.online, 30);
        assert_eq!(deserialized.printing, 10);
    }
}
