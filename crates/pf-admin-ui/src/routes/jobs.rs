// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Job queue view route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All job queries are scoped by the
//! requester's [`DataScope`](crate::scope::DataScope).

use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;

use pf_auth::middleware::RequireAuth;
use pf_common::identity::SiteId;
use pf_common::job::{
    ColorMode, CostCenter, JobId, JobStatus, MediaSize, Sides,
};

use crate::error::AdminUiError;
use crate::job_view::{JobSummary, JobViewResponse};
use crate::scope::{derive_scope, DataScope};
use crate::state::AdminState;

/// Build the `/jobs` router.
pub fn router() -> Router<AdminState> {
    Router::new().route("/", get(list_jobs))
}

/// Build stub job data scoped to the requester's authorized sites.
fn stub_jobs(scope: &DataScope) -> Vec<JobSummary> {
    let all_jobs = vec![
        JobSummary {
            job_id: JobId::generate(),
            owner_display_name: "DOE, JOHN Q.".to_string(),
            document_name: "quarterly-report.pdf".to_string(),
            status: JobStatus::Held,
            page_count: Some(12),
            copies: 1,
            sides: Sides::TwoSidedLongEdge,
            color: ColorMode::Grayscale,
            media: MediaSize::Letter,
            cost_center: CostCenter::new("CC-0001", "Test Unit")
                .expect("valid stub cost center"),
            site_id: SiteId("langley".to_string()),
            target_printer: None,
            submitted_at: Utc::now(),
            released_at: None,
            completed_at: None,
        },
        JobSummary {
            job_id: JobId::generate(),
            owner_display_name: "SMITH, JANE A.".to_string(),
            document_name: "travel-orders.pdf".to_string(),
            status: JobStatus::Printing,
            page_count: Some(3),
            copies: 2,
            sides: Sides::OneSided,
            color: ColorMode::Color,
            media: MediaSize::Letter,
            cost_center: CostCenter::new("CC-0002", "Ops Squadron")
                .expect("valid stub cost center"),
            site_id: SiteId("ramstein".to_string()),
            target_printer: Some(
                pf_common::fleet::PrinterId::new("PRN-0099")
                    .expect("valid stub printer ID"),
            ),
            submitted_at: Utc::now(),
            released_at: Some(Utc::now()),
            completed_at: None,
        },
    ];

    match scope {
        DataScope::Global => all_jobs,
        DataScope::Sites(sites) => all_jobs
            .into_iter()
            .filter(|j| sites.contains(&j.site_id))
            .collect(),
    }
}

/// `GET /jobs` — Return a scoped, paginated job listing.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester lacks admin access.
async fn list_jobs(
    RequireAuth(identity): RequireAuth,
) -> Result<Json<JobViewResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let jobs = stub_jobs(&scope);
    let total_count = jobs.len() as u64;

    Ok(Json(JobViewResponse {
        jobs,
        total_count,
        page: 1,
        page_size: 25,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_view_response_serializes() {
        let jobs = stub_jobs(&DataScope::Global);
        let response = JobViewResponse {
            total_count: jobs.len() as u64,
            jobs,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("quarterly-report.pdf"));
        assert!(json.contains("\"page\":1"));
    }

    #[test]
    fn nist_ac3_site_admin_sees_only_own_site_jobs() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Site admin for langley cannot see ramstein jobs.
        let scope = DataScope::Sites(vec![SiteId("langley".to_string())]);
        let jobs = stub_jobs(&scope);
        assert!(jobs
            .iter()
            .all(|j| j.site_id == SiteId("langley".to_string())));
        assert!(!jobs.is_empty());
    }

    #[test]
    fn nist_ac3_global_scope_sees_all_jobs() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Fleet admin sees jobs from all sites.
        let scope = DataScope::Global;
        let jobs = stub_jobs(&scope);
        let sites: Vec<&SiteId> = jobs.iter().map(|j| &j.site_id).collect();
        assert!(sites.contains(&&SiteId("langley".to_string())));
        assert!(sites.contains(&&SiteId("ramstein".to_string())));
    }
}
