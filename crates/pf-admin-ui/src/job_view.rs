// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Job queue view types for the admin dashboard: active jobs, held jobs,
//! job history, and search.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All job queries are scoped by
//! the requester's [`DataScope`](crate::scope::DataScope).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::fleet::PrinterId;
use pf_common::identity::SiteId;
use pf_common::job::{ColorMode, CostCenter, JobId, JobStatus, MediaSize, Sides};

/// A job summary row as displayed in the job queue table.
///
/// Owner EDIPI is intentionally omitted from the serialized response.
/// Only the display name is shown to prevent PII leakage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSummary {
    /// Unique job identifier.
    pub job_id: JobId,

    /// Display name of the job owner (e.g., "DOE, JOHN Q.").
    pub owner_display_name: String,

    /// Document title.
    pub document_name: String,

    /// Current job status.
    pub status: JobStatus,

    /// Number of pages.
    pub page_count: Option<u32>,

    /// Number of copies requested.
    pub copies: u16,

    /// Duplex setting.
    pub sides: Sides,

    /// Color mode.
    pub color: ColorMode,

    /// Media size.
    pub media: MediaSize,

    /// Cost center charged for this job.
    pub cost_center: CostCenter,

    /// Site where the job was submitted.
    pub site_id: SiteId,

    /// Target printer (if released or printing).
    pub target_printer: Option<PrinterId>,

    /// When the job was submitted.
    pub submitted_at: DateTime<Utc>,

    /// When the job was released (if applicable).
    pub released_at: Option<DateTime<Utc>>,

    /// When the job completed (if applicable).
    pub completed_at: Option<DateTime<Utc>>,
}

/// Filters for the job queue view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobFilter {
    /// Filter by site.
    pub site_id: Option<SiteId>,

    /// Filter by job status.
    pub status: Option<JobStatus>,

    /// Filter by cost center code.
    pub cost_center_code: Option<String>,

    /// Filter by target printer.
    pub printer_id: Option<PrinterId>,

    /// Free-text search across document name, owner name, job ID.
    pub search: Option<String>,

    /// Only show jobs submitted after this timestamp.
    pub submitted_after: Option<DateTime<Utc>>,

    /// Only show jobs submitted before this timestamp.
    pub submitted_before: Option<DateTime<Utc>>,
}

/// Sort options for the job queue view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobSortField {
    /// Sort by submission time.
    SubmittedAt,
    /// Sort by status.
    Status,
    /// Sort by owner display name.
    OwnerName,
    /// Sort by document name.
    DocumentName,
    /// Sort by page count.
    PageCount,
}

/// Paginated job view request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobViewRequest {
    /// Filters to apply.
    pub filter: JobFilter,

    /// Field to sort by.
    pub sort_by: Option<JobSortField>,

    /// Sort direction.
    pub sort_dir: crate::fleet_view::SortDirection,

    /// Page number (1-based).
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

/// Paginated job view response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobViewResponse {
    /// Job summaries for the current page.
    pub jobs: Vec<JobSummary>,

    /// Total number of jobs matching the filter.
    pub total_count: u64,

    /// Current page number.
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

/// Aggregated job statistics for dashboard widgets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatusSummary {
    /// Jobs currently held.
    pub held: u64,
    /// Jobs waiting for a printer.
    pub waiting: u64,
    /// Jobs being released.
    pub releasing: u64,
    /// Jobs actively printing.
    pub printing: u64,
    /// Jobs completed today.
    pub completed_today: u64,
    /// Jobs failed today.
    pub failed_today: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_filter_default_is_unfiltered() {
        let filter = JobFilter::default();
        assert!(filter.site_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.search.is_none());
    }

    #[test]
    fn job_status_summary_serialization() {
        let summary = JobStatusSummary {
            held: 10,
            waiting: 5,
            releasing: 1,
            printing: 3,
            completed_today: 200,
            failed_today: 2,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: JobStatusSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.held, 10);
        assert_eq!(deserialized.completed_today, 200);
    }
}
