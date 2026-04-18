// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! NATS-based sync types for replicating job metadata between edge cache
//! nodes and the central control plane.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
//! Edge nodes operate in DDIL (Denied, Disrupted, Intermittent, or Limited)
//! mode and sync when connectivity is restored.

use chrono::{DateTime, Utc};
use pf_common::identity::SiteId;
use pf_common::job::{JobId, JobMetadata, JobStatus};
use serde::{Deserialize, Serialize};

/// NATS subject prefix for job sync messages.
pub const SYNC_SUBJECT_PREFIX: &str = "printforge.jobs.sync";

/// A sync message published to NATS when a job state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSyncMessage {
    /// The site that originated this change.
    pub origin_site: SiteId,
    /// The job ID.
    pub job_id: JobId,
    /// The new status.
    pub status: JobStatus,
    /// Full metadata snapshot (for create/update).
    pub metadata: Option<JobMetadata>,
    /// Timestamp of the state change at the origin.
    pub changed_at: DateTime<Utc>,
    /// Monotonic sequence number for ordering at the origin site.
    pub sequence: u64,
}

/// The direction of a sync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDirection {
    /// Edge node pushing changes to central.
    EdgeToCentral,
    /// Central pushing changes to edge node.
    CentralToEdge,
}

/// Result of processing a batch of sync messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBatchResult {
    /// Number of messages successfully applied.
    pub applied: u64,
    /// Number of messages skipped (already up-to-date).
    pub skipped: u64,
    /// Number of conflicts detected (resolved by last-write-wins).
    pub conflicts: u64,
}

/// Trait for a sync backend that publishes and consumes job state changes.
pub trait SyncBackend: Send + Sync {
    /// Publish a job state change to the sync bus.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Sync` on NATS communication failure.
    fn publish(
        &self,
        message: &JobSyncMessage,
    ) -> impl std::future::Future<Output = Result<(), crate::error::JobQueueError>> + Send;

    /// Receive the next sync message from the given direction.
    ///
    /// Returns `None` if the subscription has ended.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Sync` on communication failure.
    fn recv(
        &self,
        direction: SyncDirection,
    ) -> impl std::future::Future<
        Output = Result<Option<JobSyncMessage>, crate::error::JobQueueError>,
    > + Send;
}

/// Build the NATS subject for a job sync message.
///
/// Format: `printforge.jobs.sync.<site-id>.<job-id>`
#[must_use]
pub fn sync_subject(site_id: &SiteId, job_id: &JobId) -> String {
    format!("{SYNC_SUBJECT_PREFIX}.{}.{}", site_id.0, job_id.as_uuid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_subject_format() {
        let site = SiteId("site-alpha".to_string());
        let job_id = JobId::generate();
        let subject = sync_subject(&site, &job_id);
        assert!(subject.starts_with("printforge.jobs.sync.site-alpha."));
    }

    #[test]
    fn sync_message_roundtrips_json() {
        let msg = JobSyncMessage {
            origin_site: SiteId("site-beta".to_string()),
            job_id: JobId::generate(),
            status: JobStatus::Held,
            metadata: None,
            changed_at: Utc::now(),
            sequence: 42,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: JobSyncMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, JobStatus::Held);
        assert_eq!(parsed.sequence, 42);
    }

    #[test]
    fn sync_batch_result_defaults() {
        let result = SyncBatchResult {
            applied: 10,
            skipped: 2,
            conflicts: 1,
        };
        assert_eq!(result.applied, 10);
        assert_eq!(result.skipped, 2);
        assert_eq!(result.conflicts, 1);
    }
}
