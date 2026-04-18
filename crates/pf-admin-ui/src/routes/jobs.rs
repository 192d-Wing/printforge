// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Job queue view route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All job queries are scoped by the
//! requester's [`DataScope`](crate::scope::DataScope) and translated into a
//! filter on the owner's `users.site_id` (installations list).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use pf_auth::middleware::RequireAuth;
use pf_common::identity::SiteId;
use pf_job_queue::AdminJobSummary;

use crate::error::AdminUiError;
use crate::job_view::{JobSummary, JobViewResponse};
use crate::scope::{derive_scope, scope_to_installations};
use crate::state::AdminState;

/// Default page size when the client does not specify one.
const DEFAULT_PAGE_SIZE: u32 = 25;

/// Build the `/jobs` router.
pub fn router() -> Router<AdminState> {
    Router::new().route("/", get(list_jobs))
}

/// `GET /jobs` — Return a scoped, paginated job listing.
///
/// Backed by
/// [`JobService::list_jobs_admin`](pf_job_queue::JobService::list_jobs_admin)
/// with a site-scope filter derived from the caller's roles. The filter
/// targets the owner's `users.site_id` column via a join, so a job
/// submitted at Langley is attributed to the Langley site admin.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` if the caller lacks an admin role.
/// - `AdminUiError::ServiceUnavailable` if the job service is not wired.
/// - `AdminUiError::Internal` on underlying job-service failure.
async fn list_jobs(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<JobViewResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let jobs = state
        .jobs
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "jobs" })?;

    let (summaries, total_count) = jobs
        .list_jobs_admin(scope_to_installations(&scope), DEFAULT_PAGE_SIZE, 0)
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    let page = summaries.into_iter().map(to_job_summary).collect();

    Ok(Json(JobViewResponse {
        jobs: page,
        total_count,
        page: 1,
        page_size: DEFAULT_PAGE_SIZE,
    }))
}

/// Map the job-queue [`AdminJobSummary`] onto the admin-ui wire type.
///
/// - `owner_display_name` falls back to the owner's EDIPI when the user
///   record carries no display name (e.g., unattributed / new provision).
/// - `site_id` is wrapped from the raw `users.site_id` string.
/// - `target_printer` is always `None` today; the `jobs` table has no
///   target printer column yet.
fn to_job_summary(s: AdminJobSummary) -> JobSummary {
    let AdminJobSummary {
        job,
        owner_display_name,
        owner_site_id,
    } = s;

    let owner_display_name = if owner_display_name.is_empty() {
        job.owner.as_str().to_string()
    } else {
        owner_display_name
    };

    JobSummary {
        job_id: job.id,
        owner_display_name,
        document_name: job.document_name,
        status: job.status,
        page_count: job.page_count,
        copies: job.options.copies,
        sides: job.options.sides,
        color: job.options.color,
        media: job.options.media,
        cost_center: job.cost_center,
        site_id: SiteId(owner_site_id),
        target_printer: None,
        submitted_at: job.submitted_at,
        released_at: job.released_at,
        completed_at: job.completed_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pf_common::identity::Edipi;
    use pf_common::job::{
        ColorMode, CostCenter, JobId, JobMetadata, JobStatus, MediaSize, PrintOptions, Sides,
    };

    fn sample_admin_summary(edipi: &str, site: &str, display_name: &str) -> AdminJobSummary {
        AdminJobSummary {
            job: JobMetadata {
                id: JobId::generate(),
                owner: Edipi::new(edipi).unwrap(),
                document_name: "report.pdf".to_string(),
                status: JobStatus::Held,
                options: PrintOptions {
                    copies: 1,
                    sides: Sides::TwoSidedLongEdge,
                    color: ColorMode::Grayscale,
                    media: MediaSize::Letter,
                },
                cost_center: CostCenter::new("CC-0001", "Test Unit").unwrap(),
                page_count: Some(12),
                submitted_at: Utc::now(),
                released_at: None,
                completed_at: None,
            },
            owner_display_name: display_name.to_string(),
            owner_site_id: site.to_string(),
        }
    }

    #[test]
    fn to_job_summary_wraps_site_id() {
        let mapped = to_job_summary(sample_admin_summary(
            "1111111111",
            "langley",
            "DOE, JOHN Q.",
        ));
        assert_eq!(mapped.site_id, SiteId("langley".to_string()));
        assert_eq!(mapped.owner_display_name, "DOE, JOHN Q.");
    }

    #[test]
    fn to_job_summary_falls_back_to_edipi_when_display_name_empty() {
        // Unattributed user — the join returned an empty display_name.
        // Fall back to the EDIPI so the UI still shows something useful.
        let mapped = to_job_summary(sample_admin_summary("1111111111", "", ""));
        assert_eq!(mapped.owner_display_name, "1111111111");
        assert_eq!(mapped.site_id, SiteId(String::new()));
    }

    #[test]
    fn to_job_summary_copies_print_options() {
        let mapped = to_job_summary(sample_admin_summary(
            "1111111111",
            "langley",
            "DOE, JOHN Q.",
        ));
        assert_eq!(mapped.sides, Sides::TwoSidedLongEdge);
        assert_eq!(mapped.color, ColorMode::Grayscale);
        assert_eq!(mapped.media, MediaSize::Letter);
        assert_eq!(mapped.copies, 1);
    }

    #[test]
    fn to_job_summary_target_printer_is_none() {
        // The jobs table has no target_printer column yet; the admin-ui
        // wire type always reports None until that migration lands.
        let mapped = to_job_summary(sample_admin_summary(
            "1111111111",
            "langley",
            "DOE, JOHN Q.",
        ));
        assert!(mapped.target_printer.is_none());
    }

    #[test]
    fn job_view_response_serializes() {
        let response = JobViewResponse {
            jobs: vec![],
            total_count: 0,
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"page\":1"));
        assert!(json.contains("\"page_size\":25"));
    }
}
