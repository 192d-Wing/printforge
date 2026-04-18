// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Report generation types for the admin dashboard: chargeback reports,
//! utilization reports, quota compliance reports.
//!
//! **NIST 800-53 Rev 5:** AU-2, AU-12 — Report generation and export are
//! auditable events.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use pf_common::identity::SiteId;

/// The kind of report to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportKind {
    /// Cost chargeback report by cost center / organization.
    Chargeback,
    /// Printer utilization report (pages, uptime, idle time).
    Utilization,
    /// Quota compliance report (users near or over quota).
    QuotaCompliance,
    /// Waste reduction report (duplex adoption, color vs. grayscale).
    WasteReduction,
}

/// Output format for report export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportFormat {
    /// JSON response for dashboard rendering.
    Json,
    /// CSV download for spreadsheet import.
    Csv,
}

/// Request to generate a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    /// The type of report.
    pub kind: ReportKind,

    /// Output format.
    pub format: ReportFormat,

    /// Start date of the reporting period (inclusive).
    pub start_date: NaiveDate,

    /// End date of the reporting period (inclusive).
    pub end_date: NaiveDate,

    /// Optional site filter. Must be within the requester's scope.
    pub site_id: Option<SiteId>,
}

/// A single row in a chargeback report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargebackRow {
    /// Cost center code.
    pub cost_center_code: String,

    /// Cost center name.
    pub cost_center_name: String,

    /// Site identifier.
    pub site_id: SiteId,

    /// Total pages printed.
    pub total_pages: u64,

    /// Total color pages printed.
    pub color_pages: u64,

    /// Total cost in cents.
    pub total_cost_cents: u64,
}

/// A single row in a utilization report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtilizationRow {
    /// Printer display name.
    pub printer_name: String,

    /// Site identifier.
    pub site_id: SiteId,

    /// Total pages printed during the period.
    pub pages_printed: u64,

    /// Uptime percentage (0.0 to 100.0).
    pub uptime_percent: f64,

    /// Average jobs per day.
    pub avg_jobs_per_day: f64,
}

/// A single row in a quota compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaComplianceRow {
    /// User display name.
    pub user_display_name: String,

    /// Organization.
    pub organization: String,

    /// Site identifier.
    pub site_id: SiteId,

    /// Quota limit for the period.
    pub quota_limit: u32,

    /// Pages used during the period.
    pub pages_used: u32,

    /// Whether the user exceeded their quota.
    pub exceeded: bool,
}

/// A single row in a waste reduction report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasteReductionRow {
    /// Site identifier.
    pub site_id: SiteId,

    /// Total jobs during the period.
    pub total_jobs: u64,

    /// Jobs printed duplex.
    pub duplex_jobs: u64,

    /// Jobs printed in grayscale.
    pub grayscale_jobs: u64,

    /// Estimated pages saved by duplex printing.
    pub pages_saved_duplex: u64,
}

/// Generated report metadata (returned after report creation).
///
/// **NIST 800-53 Rev 5:** AU-12 — Report generation is an auditable event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Unique report identifier.
    pub report_id: String,

    /// The kind of report.
    pub kind: ReportKind,

    /// When the report was generated.
    pub generated_at: DateTime<Utc>,

    /// The reporting period start.
    pub start_date: NaiveDate,

    /// The reporting period end.
    pub end_date: NaiveDate,

    /// Total number of rows in the report.
    pub row_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_request_serialization_roundtrip() {
        let req = ReportRequest {
            kind: ReportKind::Chargeback,
            format: ReportFormat::Csv,
            start_date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 1, 31).unwrap(),
            site_id: Some(SiteId("langley".to_string())),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ReportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.kind, ReportKind::Chargeback);
        assert_eq!(deserialized.format, ReportFormat::Csv);
    }

    #[test]
    fn chargeback_row_serialization() {
        let row = ChargebackRow {
            cost_center_code: "CC-001".to_string(),
            cost_center_name: "Test Unit".to_string(),
            site_id: SiteId("test-base".to_string()),
            total_pages: 1000,
            color_pages: 100,
            total_cost_cents: 5000,
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("CC-001"));
    }

    #[test]
    fn report_kind_all_variants_serialize() {
        let kinds = vec![
            ReportKind::Chargeback,
            ReportKind::Utilization,
            ReportKind::QuotaCompliance,
            ReportKind::WasteReduction,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let deserialized: ReportKind = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, kind);
        }
    }
}
