// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `JobService` trait defining the high-level print job operations.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
//! All service methods enforce ownership checks before allowing access to
//! or mutation of job data.

use std::future::Future;
use std::pin::Pin;

use pf_common::fleet::PrinterId;
use pf_common::identity::Identity;
use pf_common::job::{JobId, JobMetadata, JobStatus};

use crate::error::JobQueueError;

/// A lightweight summary of a job for listing endpoints.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JobSummary {
    /// The unique job identifier.
    pub id: JobId,
    /// The display name of the submitted document.
    pub document_name: String,
    /// The current lifecycle status.
    pub status: JobStatus,
    /// The number of pages, if known.
    pub page_count: Option<u32>,
    /// When the job was submitted.
    pub submitted_at: chrono::DateTime<chrono::Utc>,
}

impl From<&JobMetadata> for JobSummary {
    fn from(meta: &JobMetadata) -> Self {
        Self {
            id: meta.id.clone(),
            document_name: meta.document_name.clone(),
            status: meta.status,
            page_count: meta.page_count,
            submitted_at: meta.submitted_at,
        }
    }
}

/// Parameters for submitting a new print job.
#[derive(Debug, Clone)]
pub struct SubmitJobRequest {
    /// The display name of the document being printed.
    pub document_name: String,
    /// User-selected print options.
    pub options: pf_common::job::PrintOptions,
    /// Cost center for chargeback.
    pub cost_center: pf_common::job::CostCenter,
    /// Page count, if known at submission time.
    pub page_count: Option<u32>,
}

/// High-level service trait for print job operations.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
/// Implementations must verify caller identity before granting access to
/// job data or performing mutations.
pub trait JobService: Send + Sync {
    /// Submit a new print job. The job is created in `Held` status.
    ///
    /// **NIST 800-53 Rev 5:** AU-2 — Event Logging
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Validation` if inputs are invalid.
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn submit_job(
        &self,
        owner: Identity,
        request: SubmitJobRequest,
    ) -> Pin<Box<dyn Future<Output = Result<JobMetadata, JobQueueError>> + Send + '_>>;

    /// List jobs belonging to the caller.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    /// Returns only jobs owned by the caller's EDIPI.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn list_jobs(
        &self,
        caller: Identity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<JobSummary>, JobQueueError>> + Send + '_>>;

    /// Retrieve full job metadata. The caller must own the job or be an admin.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::NotFound` if the job does not exist.
    /// Returns `JobQueueError::Unauthorized` if the caller does not own the job
    /// and is not an admin.
    fn get_job(
        &self,
        caller: Identity,
        id: JobId,
    ) -> Pin<Box<dyn Future<Output = Result<JobMetadata, JobQueueError>> + Send + '_>>;

    /// Release a held job to a specific printer.
    ///
    /// Transitions the job from `Held` to `Waiting`.
    ///
    /// **NIST 800-53 Rev 5:** AC-3, AU-2
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Unauthorized` if the caller does not own the job.
    /// Returns `JobQueueError::InvalidTransition` if the job is not in `Held` status.
    fn release_job(
        &self,
        caller: Identity,
        id: JobId,
        printer_id: PrinterId,
    ) -> Pin<Box<dyn Future<Output = Result<JobMetadata, JobQueueError>> + Send + '_>>;

    /// Cancel a job by transitioning it to `Purged`.
    ///
    /// Only jobs in `Held` or terminal states (`Completed`, `Failed`) can be
    /// cancelled/purged. The caller must own the job or be an admin.
    ///
    /// **NIST 800-53 Rev 5:** AC-3, AU-2
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Unauthorized` if the caller does not own the job
    /// and is not an admin.
    /// Returns `JobQueueError::InvalidTransition` if the job cannot transition to `Purged`.
    fn cancel_job(
        &self,
        caller: Identity,
        id: JobId,
    ) -> Pin<Box<dyn Future<Output = Result<(), JobQueueError>> + Send + '_>>;
}
