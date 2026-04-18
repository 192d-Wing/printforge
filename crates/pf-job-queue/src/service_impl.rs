// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default implementation of [`JobService`] backed by a [`JobRepository`].
//!
//! **NIST 800-53 Rev 5:** AC-3, AU-2, AU-12
//! Enforces ownership checks and emits audit-relevant log events on every
//! state transition.

use chrono::Utc;
use pf_common::fleet::PrinterId;
use pf_common::identity::{Identity, Role};
use pf_common::job::{JobId, JobMetadata, JobStatus};
use tracing::{info, warn};

use crate::error::JobQueueError;
use crate::lifecycle;
use crate::repository::JobRepository;
use crate::service::{AdminJobSummary, JobService, JobSummary, SubmitJobRequest};

/// Determines whether the caller is authorized to access or mutate the given job.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// Returns `Ok(())` if the caller owns the job or has an admin role
/// (`FleetAdmin` or `SiteAdmin`).
fn authorize_caller(caller: &Identity, job: &JobMetadata) -> Result<(), JobQueueError> {
    // Owner always has access.
    if caller.edipi.as_str() == job.owner.as_str() {
        return Ok(());
    }

    // Admins (FleetAdmin, SiteAdmin) have access.
    let is_admin = caller.roles.iter().any(|r| {
        matches!(r, Role::FleetAdmin | Role::SiteAdmin(_))
    });

    if is_admin {
        return Ok(());
    }

    warn!(
        caller = %caller.edipi,
        job_id = %job.id.as_uuid(),
        "unauthorized job access attempt"
    );
    Err(JobQueueError::Unauthorized)
}

/// Default [`JobService`] implementation backed by a generic [`JobRepository`].
///
/// Uses generics instead of `dyn JobRepository` because the repository trait
/// uses return-position `impl Trait` (RPITIT), which is not object-safe.
pub struct JobServiceImpl<R: JobRepository> {
    repo: R,
}

impl<R: JobRepository> JobServiceImpl<R> {
    /// Create a new `JobServiceImpl` backed by the given repository.
    #[must_use]
    pub fn new(repo: R) -> Self {
        Self { repo }
    }
}

impl<R: JobRepository + Send + Sync + 'static> JobService for JobServiceImpl<R> {
    /// Submit a new print job in `Held` status.
    ///
    /// **NIST 800-53 Rev 5:** AU-2 — Event Logging
    /// **Evidence:** Logs `JOB_SUBMITTED` with owner EDIPI and job ID.
    fn submit_job(
        &self,
        owner: Identity,
        request: SubmitJobRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<JobMetadata, JobQueueError>> + Send + '_>> {
        Box::pin(async move {
            let job = JobMetadata {
                id: JobId::generate(),
                owner: owner.edipi.clone(),
                document_name: request.document_name,
                status: JobStatus::Held,
                options: request.options,
                cost_center: request.cost_center,
                page_count: request.page_count,
                submitted_at: Utc::now(),
                released_at: None,
                completed_at: None,
            };

            self.repo.insert(&job).await?;

            info!(
                job_id = %job.id.as_uuid(),
                owner = %owner.edipi,
                status = ?job.status,
                "job submitted"
            );

            Ok(job)
        })
    }

    /// List jobs belonging to the caller's EDIPI.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    /// Returns only the caller's own jobs unless the caller is an admin,
    /// in which case behaviour may be extended in the future.
    fn list_jobs(
        &self,
        caller: Identity,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<JobSummary>, JobQueueError>> + Send + '_>> {
        Box::pin(async move {
            let jobs = self.repo.list_by_owner(&caller.edipi).await?;
            let summaries = jobs.iter().map(JobSummary::from).collect();
            Ok(summaries)
        })
    }

    /// Retrieve full job metadata with ownership/admin check.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    /// **Evidence:** Returns `Err(Unauthorized)` when caller is neither owner nor admin.
    fn get_job(
        &self,
        caller: Identity,
        id: JobId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<JobMetadata, JobQueueError>> + Send + '_>> {
        Box::pin(async move {
            let job = self.repo.get_by_id(&id).await?;
            authorize_caller(&caller, &job)?;
            Ok(job)
        })
    }

    /// Release a held job to a specific printer.
    ///
    /// Transitions `Held` -> `Waiting` via the lifecycle state machine.
    ///
    /// **NIST 800-53 Rev 5:** AC-3, AU-2
    fn release_job(
        &self,
        caller: Identity,
        id: JobId,
        _printer_id: PrinterId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<JobMetadata, JobQueueError>> + Send + '_>> {
        Box::pin(async move {
            let job = self.repo.get_by_id(&id).await?;
            authorize_caller(&caller, &job)?;

            // Validate the transition via the state machine.
            let _transition = lifecycle::transition(
                &job,
                JobStatus::Waiting,
                &caller.edipi,
                // Use a placeholder source IP; the API gateway layer provides the real one.
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            )?;

            self.repo.update_status(&id, JobStatus::Waiting).await?;

            // Re-fetch to return updated metadata.
            let updated = self.repo.get_by_id(&id).await?;

            info!(
                job_id = %id.as_uuid(),
                caller = %caller.edipi,
                status = ?updated.status,
                "job released"
            );

            Ok(updated)
        })
    }

    /// Cancel a job by transitioning it to `Purged`.
    ///
    /// For jobs in `Held` status, we walk through the state machine:
    /// `Held` -> `Waiting` -> ... is not appropriate for cancellation, so
    /// we treat `Held` as a special case that can be directly cancelled
    /// (the lifecycle state machine allows `Completed`/`Failed` -> `Purged`,
    /// but for cancellation of held jobs we mark them `Failed` then `Purged`).
    ///
    /// **NIST 800-53 Rev 5:** AC-3, AU-2
    fn cancel_job(
        &self,
        caller: Identity,
        id: JobId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), JobQueueError>> + Send + '_>> {
        Box::pin(async move {
            let job = self.repo.get_by_id(&id).await?;
            authorize_caller(&caller, &job)?;

            let source_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

            match job.status {
                // Terminal states can transition directly to Purged.
                JobStatus::Completed | JobStatus::Failed => {
                    lifecycle::transition(&job, JobStatus::Purged, &caller.edipi, source_ip)?;
                    self.repo.update_status(&id, JobStatus::Purged).await?;
                }
                // Held jobs: transition to Failed first, then Purged.
                JobStatus::Held => {
                    // Direct Held -> Purged is not valid in the state machine.
                    // We mark as Failed (via update_status) then Purged.
                    // This is a cancellation shortcut: we bypass the state machine
                    // validation for the intermediate step and use mark_purged.
                    self.repo.mark_purged(std::slice::from_ref(&id)).await?;
                }
                // Any other active state cannot be cancelled.
                _ => {
                    return Err(JobQueueError::InvalidTransition {
                        from: job.status,
                        to: JobStatus::Purged,
                    });
                }
            }

            info!(
                job_id = %id.as_uuid(),
                caller = %caller.edipi,
                "job cancelled"
            );

            Ok(())
        })
    }

    fn list_jobs_admin(
        &self,
        installations: Vec<String>,
        limit: u32,
        offset: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(Vec<AdminJobSummary>, u64), JobQueueError>> + Send + '_>> {
        Box::pin(async move {
            self.repo
                .list_admin_scoped(&installations, limit, offset)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use pf_common::identity::{Edipi, Role, SiteId};
    use pf_common::job::{CostCenter, PrintOptions};

    use super::*;
    use crate::retention::RetentionQuery;

    // -----------------------------------------------------------------------
    // In-memory mock repository
    // -----------------------------------------------------------------------

    struct InMemoryJobRepository {
        jobs: Mutex<HashMap<uuid::Uuid, JobMetadata>>,
        /// Optional directory mapping `owner_edipi` to `(display_name, site_id)`,
        /// used by `list_admin_scoped` to simulate the `JOIN` on the `users` table.
        user_directory: Mutex<HashMap<String, (String, String)>>,
    }

    impl InMemoryJobRepository {
        fn new() -> Self {
            Self {
                jobs: Mutex::new(HashMap::new()),
                user_directory: Mutex::new(HashMap::new()),
            }
        }

        /// Seed the in-memory user directory for tests that exercise
        /// `list_admin_scoped`. Maps `owner_edipi` to `(display_name, site_id)`.
        fn set_user(&self, edipi: &str, display_name: &str, site_id: &str) {
            let mut dir = self.user_directory.lock().unwrap();
            dir.insert(
                edipi.to_string(),
                (display_name.to_string(), site_id.to_string()),
            );
        }
    }

    impl JobRepository for InMemoryJobRepository {
        async fn insert(&self, job: &JobMetadata) -> Result<(), JobQueueError> {
            let mut map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            map.insert(*job.id.as_uuid(), job.clone());
            Ok(())
        }

        async fn get_by_id(&self, id: &JobId) -> Result<JobMetadata, JobQueueError> {
            let map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            map.get(id.as_uuid())
                .cloned()
                .ok_or(JobQueueError::NotFound)
        }

        async fn list_by_owner(
            &self,
            owner: &Edipi,
        ) -> Result<Vec<JobMetadata>, JobQueueError> {
            let map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            let results: Vec<JobMetadata> = map
                .values()
                .filter(|j| j.owner.as_str() == owner.as_str())
                .cloned()
                .collect();
            Ok(results)
        }

        async fn list_by_status(
            &self,
            status: JobStatus,
        ) -> Result<Vec<JobMetadata>, JobQueueError> {
            let map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            let results: Vec<JobMetadata> = map
                .values()
                .filter(|j| j.status == status)
                .cloned()
                .collect();
            Ok(results)
        }

        async fn update_status(
            &self,
            id: &JobId,
            new_status: JobStatus,
        ) -> Result<(), JobQueueError> {
            let mut map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            let job = map
                .get_mut(id.as_uuid())
                .ok_or(JobQueueError::NotFound)?;
            job.status = new_status;
            if matches!(new_status, JobStatus::Waiting | JobStatus::Releasing) {
                job.released_at = Some(Utc::now());
            }
            if matches!(new_status, JobStatus::Completed | JobStatus::Failed) {
                job.completed_at = Some(Utc::now());
            }
            Ok(())
        }

        async fn find_purgeable(
            &self,
            _query: &RetentionQuery,
        ) -> Result<Vec<JobMetadata>, JobQueueError> {
            Ok(vec![])
        }

        async fn mark_purged(&self, ids: &[JobId]) -> Result<u64, JobQueueError> {
            let mut map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            let mut count: u64 = 0;
            for id in ids {
                if let Some(job) = map.get_mut(id.as_uuid()) {
                    if job.status != JobStatus::Purged {
                        job.status = JobStatus::Purged;
                        count += 1;
                    }
                }
            }
            Ok(count)
        }

        async fn list_admin_scoped(
            &self,
            installations: &[String],
            limit: u32,
            offset: u32,
        ) -> Result<(Vec<AdminJobSummary>, u64), JobQueueError> {
            // The in-memory mock has no users table to join against. Tests
            // that need installation scoping can inject an owner_edipi ->
            // (display_name, site_id) directory, but by default we return
            // every job with empty owner metadata — which is sufficient to
            // exercise pagination and service-layer plumbing.
            let directory = self.user_directory.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;
            let map = self.jobs.lock().map_err(|e| {
                JobQueueError::Repository(format!("lock poisoned: {e}").into())
            })?;

            let mut all: Vec<(JobMetadata, String, String)> = map
                .values()
                .map(|j| {
                    let (name, site) = directory
                        .get(j.owner.as_str())
                        .cloned()
                        .unwrap_or_default();
                    (j.clone(), name, site)
                })
                .filter(|(_, _, site)| {
                    installations.is_empty() || installations.iter().any(|i| i == site)
                })
                .collect();

            // Newest first, to mirror pg_repo's ORDER BY submitted_at DESC.
            all.sort_by(|a, b| b.0.submitted_at.cmp(&a.0.submitted_at));

            let total = all.len() as u64;
            let offset = offset as usize;
            let limit = limit as usize;
            let page = all
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(job, owner_display_name, owner_site_id)| AdminJobSummary {
                    job,
                    owner_display_name,
                    owner_site_id,
                })
                .collect();

            Ok((page, total))
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_identity(edipi: &str, roles: Vec<Role>) -> Identity {
        Identity {
            edipi: Edipi::new(edipi).unwrap(),
            name: "DOE.JOHN.Q".to_string(),
            org: "Test Unit, Test Base AFB".to_string(),
            roles,
        }
    }

    fn make_user(edipi: &str) -> Identity {
        make_identity(edipi, vec![Role::User])
    }

    fn make_admin(edipi: &str) -> Identity {
        make_identity(edipi, vec![Role::FleetAdmin])
    }

    fn make_site_admin(edipi: &str) -> Identity {
        make_identity(edipi, vec![Role::SiteAdmin(SiteId("SITE-001".to_string()))])
    }

    fn make_submit_request() -> SubmitJobRequest {
        SubmitJobRequest {
            document_name: "test-document.pdf".to_string(),
            options: PrintOptions::default(),
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            page_count: Some(5),
        }
    }

    fn make_service() -> JobServiceImpl<InMemoryJobRepository> {
        JobServiceImpl::new(InMemoryJobRepository::new())
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn submit_job_returns_held_status() {
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();

        let job = svc.submit_job(owner.clone(), req).await.unwrap();

        assert_eq!(job.status, JobStatus::Held);
        assert_eq!(job.owner.as_str(), "1234567890");
        assert_eq!(job.document_name, "test-document.pdf");
        assert_eq!(job.page_count, Some(5));
        assert!(job.released_at.is_none());
        assert!(job.completed_at.is_none());
    }

    #[tokio::test]
    async fn nist_ac3_get_job_by_owner_succeeds() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Owner can retrieve their own job.
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        let fetched = svc.get_job(owner.clone(), submitted.id.clone()).await.unwrap();

        assert_eq!(fetched.id.as_uuid(), submitted.id.as_uuid());
    }

    #[tokio::test]
    async fn nist_ac3_get_job_by_non_owner_returns_unauthorized() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Non-owner, non-admin caller is denied.
        let svc = make_service();
        let owner = make_user("1234567890");
        let other = make_user("0987654321");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        let result = svc.get_job(other.clone(), submitted.id.clone()).await;

        assert!(matches!(result, Err(JobQueueError::Unauthorized)));
    }

    #[tokio::test]
    async fn nist_ac3_admin_can_get_any_job() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: FleetAdmin can access any user's job.
        let svc = make_service();
        let owner = make_user("1234567890");
        let admin = make_admin("0987654321");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        let fetched = svc.get_job(admin.clone(), submitted.id.clone()).await.unwrap();

        assert_eq!(fetched.id.as_uuid(), submitted.id.as_uuid());
    }

    #[tokio::test]
    async fn nist_ac3_site_admin_can_get_any_job() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: SiteAdmin can access any user's job.
        let svc = make_service();
        let owner = make_user("1234567890");
        let admin = make_site_admin("0987654321");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        let fetched = svc.get_job(admin.clone(), submitted.id.clone()).await.unwrap();

        assert_eq!(fetched.id.as_uuid(), submitted.id.as_uuid());
    }

    #[tokio::test]
    async fn release_job_transitions_to_waiting() {
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();
        let printer = PrinterId::new("PRN-0042").unwrap();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        assert_eq!(submitted.status, JobStatus::Held);

        let released = svc.release_job(owner.clone(), submitted.id.clone(), printer.clone()).await.unwrap();
        assert_eq!(released.status, JobStatus::Waiting);
    }

    #[tokio::test]
    async fn nist_ac3_release_by_non_owner_returns_unauthorized() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        let svc = make_service();
        let owner = make_user("1234567890");
        let other = make_user("0987654321");
        let req = make_submit_request();
        let printer = PrinterId::new("PRN-0042").unwrap();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        let result = svc.release_job(other.clone(), submitted.id.clone(), printer.clone()).await;

        assert!(matches!(result, Err(JobQueueError::Unauthorized)));
    }

    #[tokio::test]
    async fn cancel_held_job_succeeds() {
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();
        let result = svc.cancel_job(owner.clone(), submitted.id.clone()).await;

        assert!(result.is_ok());

        // Verify the job is now purged.
        let fetched = svc.get_job(owner.clone(), submitted.id.clone()).await.unwrap();
        assert_eq!(fetched.status, JobStatus::Purged);
    }

    #[tokio::test]
    async fn cancel_completed_job_succeeds() {
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();

        // Walk the job through to Completed via the repo directly.
        svc.repo.update_status(&submitted.id, JobStatus::Waiting).await.unwrap();
        svc.repo.update_status(&submitted.id, JobStatus::Releasing).await.unwrap();
        svc.repo.update_status(&submitted.id, JobStatus::Printing).await.unwrap();
        svc.repo.update_status(&submitted.id, JobStatus::Completed).await.unwrap();

        let result = svc.cancel_job(owner.clone(), submitted.id.clone()).await;
        assert!(result.is_ok());

        let fetched = svc.get_job(owner.clone(), submitted.id.clone()).await.unwrap();
        assert_eq!(fetched.status, JobStatus::Purged);
    }

    #[tokio::test]
    async fn cancel_active_job_returns_invalid_transition() {
        // A job that is currently Printing cannot be cancelled.
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();

        // Move to Printing.
        svc.repo.update_status(&submitted.id, JobStatus::Waiting).await.unwrap();
        svc.repo.update_status(&submitted.id, JobStatus::Releasing).await.unwrap();
        svc.repo.update_status(&submitted.id, JobStatus::Printing).await.unwrap();

        let result = svc.cancel_job(owner.clone(), submitted.id.clone()).await;
        assert!(matches!(
            result,
            Err(JobQueueError::InvalidTransition { .. })
        ));
    }

    #[tokio::test]
    async fn list_jobs_returns_only_callers_jobs() {
        let svc = make_service();
        let user_a = make_user("1234567890");
        let user_b = make_user("0987654321");

        // Submit 2 jobs for user A and 1 for user B.
        svc.submit_job(user_a.clone(), make_submit_request()).await.unwrap();
        svc.submit_job(user_a.clone(), make_submit_request()).await.unwrap();
        svc.submit_job(user_b.clone(), make_submit_request()).await.unwrap();

        let a_jobs = svc.list_jobs(user_a.clone()).await.unwrap();
        let b_jobs = svc.list_jobs(user_b.clone()).await.unwrap();

        assert_eq!(a_jobs.len(), 2);
        assert_eq!(b_jobs.len(), 1);
    }

    #[tokio::test]
    async fn get_nonexistent_job_returns_not_found() {
        let svc = make_service();
        let user = make_user("1234567890");
        let fake_id = JobId::generate();

        let result = svc.get_job(user.clone(), fake_id.clone()).await;
        assert!(matches!(result, Err(JobQueueError::NotFound)));
    }

    #[tokio::test]
    async fn nist_ac3_list_jobs_admin_enforces_site_scope() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: list_jobs_admin with a non-empty installation list
        // returns only jobs whose owner sits at one of those installations.
        let repo = InMemoryJobRepository::new();
        repo.set_user("1111111111", "DOE, JOHN Q.", "langley");
        repo.set_user("2222222222", "SMITH, JANE A.", "ramstein");
        let svc = JobServiceImpl::new(repo);

        let langley_owner = make_user("1111111111");
        let ramstein_owner = make_user("2222222222");
        svc.submit_job(langley_owner, make_submit_request()).await.unwrap();
        svc.submit_job(ramstein_owner, make_submit_request()).await.unwrap();

        let (page, total) = svc
            .list_jobs_admin(vec!["langley".to_string()], 25, 0)
            .await
            .unwrap();

        assert_eq!(total, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].owner_site_id, "langley");
        assert_eq!(page[0].owner_display_name, "DOE, JOHN Q.");
    }

    #[tokio::test]
    async fn list_jobs_admin_global_scope_returns_all_jobs() {
        let repo = InMemoryJobRepository::new();
        repo.set_user("1111111111", "DOE, JOHN Q.", "langley");
        repo.set_user("2222222222", "SMITH, JANE A.", "ramstein");
        let svc = JobServiceImpl::new(repo);

        svc.submit_job(make_user("1111111111"), make_submit_request()).await.unwrap();
        svc.submit_job(make_user("2222222222"), make_submit_request()).await.unwrap();

        let (page, total) = svc.list_jobs_admin(Vec::new(), 25, 0).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(page.len(), 2);
    }

    #[tokio::test]
    async fn list_jobs_admin_paginates() {
        let repo = InMemoryJobRepository::new();
        repo.set_user("1111111111", "DOE, JOHN Q.", "langley");
        let svc = JobServiceImpl::new(repo);

        for _ in 0..5 {
            svc.submit_job(make_user("1111111111"), make_submit_request()).await.unwrap();
        }

        let (page1, total) = svc.list_jobs_admin(Vec::new(), 2, 0).await.unwrap();
        let (page2, _) = svc.list_jobs_admin(Vec::new(), 2, 2).await.unwrap();
        let (page3, _) = svc.list_jobs_admin(Vec::new(), 2, 4).await.unwrap();

        assert_eq!(total, 5);
        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);
    }

    #[tokio::test]
    async fn cancel_already_purged_job_returns_error() {
        let svc = make_service();
        let owner = make_user("1234567890");
        let req = make_submit_request();

        let submitted = svc.submit_job(owner.clone(), req).await.unwrap();

        // Cancel once (Held -> Purged via mark_purged).
        svc.cancel_job(owner.clone(), submitted.id.clone()).await.unwrap();

        // Attempting to cancel again should fail (AlreadyPurged).
        let result = svc.cancel_job(owner.clone(), submitted.id.clone()).await;
        assert!(result.is_err());
    }
}
