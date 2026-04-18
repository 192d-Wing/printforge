// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Job release logic: authorization check, spool retrieval, and transition
//! from `Held` → `Waiting`.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
//! Only the job owner (matching EDIPI) may release a held job.

use pf_common::fleet::PrinterId;
use pf_common::identity::Edipi;
use pf_common::job::{JobId, JobMetadata, JobStatus};
use serde::{Deserialize, Serialize};

use crate::error::JobQueueError;

/// A request to release a held print job to a specific printer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// The ID of the job to release.
    pub job_id: JobId,
    /// The EDIPI of the user requesting release (from JWT / CAC).
    pub requestor: Edipi,
    /// The target printer where the job should be printed.
    pub target_printer: PrinterId,
}

/// The result of a successful job release operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseResult {
    /// The job ID that was released.
    pub job_id: JobId,
    /// The new status after release (should be `Waiting`).
    pub status: JobStatus,
    /// The target printer.
    pub target_printer: PrinterId,
}

/// Verify that the requestor is authorized to release the job.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// Currently this enforces owner-only release: the requesting user's EDIPI
/// must match the job owner's EDIPI.
///
/// # Errors
///
/// Returns `JobQueueError::Unauthorized` if the requestor is not the job owner.
/// Returns `JobQueueError::InvalidTransition` if the job is not in `Held` status.
/// Returns `JobQueueError::AlreadyPurged` if the job has been purged.
pub fn authorize_release(job: &JobMetadata, requestor: &Edipi) -> Result<(), JobQueueError> {
    if job.status == JobStatus::Purged {
        return Err(JobQueueError::AlreadyPurged);
    }

    if job.status != JobStatus::Held {
        return Err(JobQueueError::InvalidTransition {
            from: job.status,
            to: JobStatus::Waiting,
        });
    }

    if job.owner.as_str() != requestor.as_str() {
        return Err(JobQueueError::Unauthorized);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pf_common::job::{CostCenter, PrintOptions};

    use super::*;

    fn make_held_job(owner_edipi: &str) -> JobMetadata {
        JobMetadata {
            id: JobId::generate(),
            owner: Edipi::new(owner_edipi).unwrap(),
            document_name: "test.pdf".to_string(),
            status: JobStatus::Held,
            options: PrintOptions::default(),
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            page_count: Some(5),
            target_printer: None,
            submitted_at: Utc::now(),
            released_at: None,
            completed_at: None,
        }
    }

    #[test]
    fn nist_ac3_owner_can_release() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        let job = make_held_job("1234567890");
        let requestor = Edipi::new("1234567890").unwrap();
        assert!(authorize_release(&job, &requestor).is_ok());
    }

    #[test]
    fn nist_ac3_non_owner_cannot_release() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        let job = make_held_job("1234567890");
        let other = Edipi::new("0987654321").unwrap();
        let result = authorize_release(&job, &other);
        assert!(matches!(result, Err(JobQueueError::Unauthorized)));
    }

    #[test]
    fn rejects_release_of_non_held_job() {
        let mut job = make_held_job("1234567890");
        job.status = JobStatus::Printing;
        let requestor = Edipi::new("1234567890").unwrap();
        let result = authorize_release(&job, &requestor);
        assert!(matches!(
            result,
            Err(JobQueueError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn rejects_release_of_purged_job() {
        let mut job = make_held_job("1234567890");
        job.status = JobStatus::Purged;
        let requestor = Edipi::new("1234567890").unwrap();
        let result = authorize_release(&job, &requestor);
        assert!(matches!(result, Err(JobQueueError::AlreadyPurged)));
    }
}
