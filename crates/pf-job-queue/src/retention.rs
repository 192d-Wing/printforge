// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Auto-purge of expired jobs based on configurable retention policies.
//!
//! **NIST 800-53 Rev 5:** AU-11 — Audit Record Retention
//! Job metadata and spool data are retained for the configured TTL,
//! then automatically purged with an audit trail.

use std::time::Duration;

use chrono::{DateTime, Utc};
use pf_common::job::{JobMetadata, JobStatus};

/// Determine whether a job is eligible for purge based on its terminal
/// status and the configured retention TTL.
///
/// Only jobs in `Completed`, `Failed`, or `Purged` (idempotent) status
/// are candidates. A job is eligible if the elapsed time since completion
/// or failure exceeds `retention_ttl`.
#[must_use]
pub fn is_eligible_for_purge(job: &JobMetadata, retention_ttl: Duration) -> bool {
    let terminal_time = match job.status {
        JobStatus::Completed | JobStatus::Failed => job.completed_at,
        // Non-terminal or already-purged states are never eligible.
        _ => return false,
    };

    let Some(completed) = terminal_time else {
        // Defensive: if completed_at is missing on a terminal job,
        // fall back to submitted_at.
        return elapsed_exceeds(job.submitted_at, retention_ttl);
    };

    elapsed_exceeds(completed, retention_ttl)
}

/// Check whether the time elapsed since `since` exceeds the given duration.
fn elapsed_exceeds(since: DateTime<Utc>, ttl: Duration) -> bool {
    let Ok(chrono_ttl) = chrono::Duration::from_std(ttl) else {
        return false;
    };
    Utc::now().signed_duration_since(since) > chrono_ttl
}

/// Criteria for a retention sweep query.
#[derive(Debug, Clone)]
pub struct RetentionQuery {
    /// Only purge jobs older than this TTL after reaching terminal status.
    pub retention_ttl: Duration,
    /// Maximum number of jobs to purge in this sweep.
    pub batch_size: u32,
}

/// Result of a retention sweep.
#[derive(Debug, Clone)]
pub struct RetentionSweepResult {
    /// Number of jobs transitioned to `Purged`.
    pub purged_count: u64,
    /// Number of spool payloads deleted.
    pub spool_deleted_count: u64,
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;
    use pf_common::identity::Edipi;
    use pf_common::job::{CostCenter, JobId, PrintOptions};

    use super::*;

    fn make_job(status: JobStatus, completed_at: Option<DateTime<Utc>>) -> JobMetadata {
        JobMetadata {
            id: JobId::generate(),
            owner: Edipi::new("1234567890").unwrap(),
            document_name: "test.pdf".to_string(),
            status,
            options: PrintOptions::default(),
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            page_count: Some(5),
            target_printer: None,
            submitted_at: Utc::now() - ChronoDuration::hours(100),
            released_at: None,
            completed_at,
        }
    }

    #[test]
    fn completed_job_past_ttl_is_eligible() {
        let completed_at = Utc::now() - ChronoDuration::hours(80);
        let job = make_job(JobStatus::Completed, Some(completed_at));
        assert!(is_eligible_for_purge(&job, Duration::from_secs(72 * 3600)));
    }

    #[test]
    fn completed_job_within_ttl_is_not_eligible() {
        let completed_at = Utc::now() - ChronoDuration::hours(1);
        let job = make_job(JobStatus::Completed, Some(completed_at));
        assert!(!is_eligible_for_purge(&job, Duration::from_secs(72 * 3600)));
    }

    #[test]
    fn failed_job_past_ttl_is_eligible() {
        let completed_at = Utc::now() - ChronoDuration::hours(80);
        let job = make_job(JobStatus::Failed, Some(completed_at));
        assert!(is_eligible_for_purge(&job, Duration::from_secs(72 * 3600)));
    }

    #[test]
    fn held_job_is_never_eligible() {
        let job = make_job(JobStatus::Held, None);
        assert!(!is_eligible_for_purge(&job, Duration::from_secs(0)));
    }

    #[test]
    fn purged_job_is_not_eligible_again() {
        let completed_at = Utc::now() - ChronoDuration::hours(80);
        let job = make_job(JobStatus::Purged, Some(completed_at));
        assert!(!is_eligible_for_purge(&job, Duration::from_secs(0)));
    }

    #[test]
    fn completed_job_without_timestamp_falls_back_to_submitted() {
        // Defensive: if completed_at is None, use submitted_at
        let job = make_job(JobStatus::Completed, None);
        // submitted_at is 100 hours ago, TTL is 72 hours — should be eligible
        assert!(is_eligible_for_purge(&job, Duration::from_secs(72 * 3600)));
    }
}
