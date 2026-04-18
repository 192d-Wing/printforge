// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for job metadata persistence.
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! Implementations must ensure that audit-related metadata (state transitions,
//! timestamps) is append-only and cannot be retroactively modified.

use pf_common::identity::Edipi;
use pf_common::job::{JobId, JobMetadata, JobStatus};

use crate::error::JobQueueError;
use crate::retention::RetentionQuery;
use crate::service::AdminJobSummary;

/// Repository trait for persisting and querying job metadata.
///
/// Implementations back this with `PostgreSQL` (central) or `SQLite` (edge
/// cache node).
pub trait JobRepository: Send + Sync {
    /// Insert a new job into the repository.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn insert(
        &self,
        job: &JobMetadata,
    ) -> impl std::future::Future<Output = Result<(), JobQueueError>> + Send;

    /// Retrieve a job by its ID.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::NotFound` if the job does not exist.
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn get_by_id(
        &self,
        id: &JobId,
    ) -> impl std::future::Future<Output = Result<JobMetadata, JobQueueError>> + Send;

    /// List all jobs owned by a specific user.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn list_by_owner(
        &self,
        owner: &Edipi,
    ) -> impl std::future::Future<Output = Result<Vec<JobMetadata>, JobQueueError>> + Send;

    /// List all jobs in a given status.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn list_by_status(
        &self,
        status: JobStatus,
    ) -> impl std::future::Future<Output = Result<Vec<JobMetadata>, JobQueueError>> + Send;

    /// Update the status of a job. This is an append-style operation:
    /// the previous status is preserved in the audit log.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::NotFound` if the job does not exist.
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn update_status(
        &self,
        id: &JobId,
        new_status: JobStatus,
    ) -> impl std::future::Future<Output = Result<(), JobQueueError>> + Send;

    /// Find jobs eligible for retention purge.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn find_purgeable(
        &self,
        query: &RetentionQuery,
    ) -> impl std::future::Future<Output = Result<Vec<JobMetadata>, JobQueueError>> + Send;

    /// Mark a batch of jobs as purged.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn mark_purged(
        &self,
        ids: &[JobId],
    ) -> impl std::future::Future<Output = Result<u64, JobQueueError>> + Send;

    /// List jobs for the admin dashboard, joining `users` to enrich each row
    /// with `owner_display_name` and `owner_site_id`. When `installations` is
    /// non-empty, only jobs whose owner's `users.site_id` is in the set are
    /// returned.
    ///
    /// Returns a tuple of `(page, total_count)` where `total_count` reflects
    /// the filter before pagination.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Repository` on persistence failure.
    fn list_admin_scoped(
        &self,
        installations: &[String],
        limit: u32,
        offset: u32,
    ) -> impl std::future::Future<Output = Result<(Vec<AdminJobSummary>, u64), JobQueueError>> + Send;
}
