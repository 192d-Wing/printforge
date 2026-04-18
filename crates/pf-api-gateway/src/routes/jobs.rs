// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Job management routes: submit, list, get, release, and cancel print jobs.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement (all routes require auth),
//! SI-10 — Information Input Validation (request payloads validated).

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterId;
use pf_common::job::{ColorMode, CostCenter, JobId, JobStatus, MediaSize, PrintOptions, Sides};

use crate::error::ApiError;
use crate::middleware::auth::RequireAuth;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Request payload for submitting a new print job.
#[derive(Debug, Deserialize)]
pub struct SubmitJobRequest {
    /// Human-readable document name.
    pub document_name: String,
    /// Number of copies.
    pub copies: Option<u16>,
    /// Duplex setting.
    pub sides: Option<Sides>,
    /// Color mode.
    pub color: Option<ColorMode>,
    /// Media size.
    pub media: Option<MediaSize>,
    /// Cost-center code for chargeback.
    pub cost_center_code: String,
    /// Cost-center display name.
    pub cost_center_name: String,
}

/// Response returned after a job is successfully submitted.
#[derive(Debug, Serialize)]
pub struct SubmitJobResponse {
    /// The newly-created job identifier.
    pub job_id: JobId,
    /// Current job status (will be `Held` for Follow-Me).
    pub status: JobStatus,
    /// Submission timestamp.
    pub submitted_at: DateTime<Utc>,
}

/// Query parameters for listing jobs.
#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    /// Optional status filter.
    pub status: Option<JobStatus>,
    /// Maximum number of results (default 50).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// A single job entry in a list response.
#[derive(Debug, Serialize)]
pub struct JobSummary {
    /// Job identifier.
    pub id: JobId,
    /// Document name.
    pub document_name: String,
    /// Current status.
    pub status: JobStatus,
    /// Submission timestamp.
    pub submitted_at: DateTime<Utc>,
    /// Page count, if known.
    pub page_count: Option<u32>,
}

/// Response for listing jobs.
#[derive(Debug, Serialize)]
pub struct ListJobsResponse {
    /// The matching jobs.
    pub jobs: Vec<JobSummary>,
    /// Total number of matching jobs (for pagination).
    pub total: u64,
}

/// Detailed job response (single-job fetch).
#[derive(Debug, Serialize)]
pub struct JobDetailResponse {
    /// Job identifier.
    pub id: JobId,
    /// Document name.
    pub document_name: String,
    /// Current status.
    pub status: JobStatus,
    /// Print options.
    pub options: PrintOptions,
    /// Cost center.
    pub cost_center: CostCenter,
    /// Page count, if known.
    pub page_count: Option<u32>,
    /// Submission timestamp.
    pub submitted_at: DateTime<Utc>,
    /// Release timestamp, if applicable.
    pub released_at: Option<DateTime<Utc>>,
    /// Completion timestamp, if applicable.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request payload for releasing a held job.
#[derive(Debug, Deserialize)]
pub struct ReleaseJobRequest {
    /// Target printer to release the job to.
    pub printer_id: String,
}

/// Response after releasing a job.
#[derive(Debug, Serialize)]
pub struct ReleaseJobResponse {
    /// The job identifier.
    pub job_id: JobId,
    /// Updated job status.
    pub status: JobStatus,
    /// Target printer identifier.
    pub printer_id: String,
}

/// Response after cancelling a job.
#[derive(Debug, Serialize)]
pub struct CancelJobResponse {
    /// The cancelled job identifier.
    pub job_id: JobId,
    /// Updated job status.
    pub status: JobStatus,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the `/jobs` router.
///
/// All routes require authentication via `RequireAuth`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(submit_job).get(list_jobs))
        .route("/{id}", get(get_job).delete(cancel_job))
        .route("/{id}/release", post(release_job))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Submit a new print job.
///
/// Accepts a `SubmitJobRequest` payload and creates a held Follow-Me job.
///
/// **NIST 800-53 Rev 5:** AC-3 — requires authenticated user.
///
/// # Errors
///
/// Returns `ApiError` on validation failure or internal error.
async fn submit_job(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Json(req): Json<SubmitJobRequest>,
) -> Result<Json<SubmitJobResponse>, ApiError> {
    let svc = state.job_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let cost_center = CostCenter::new(&req.cost_center_code, &req.cost_center_name)
        .map_err(|e| ApiError::bad_request(Uuid::now_v7(), e.to_string()))?;

    let options = PrintOptions {
        copies: req.copies.unwrap_or(1),
        sides: req.sides.unwrap_or(Sides::OneSided),
        color: req.color.unwrap_or(ColorMode::Grayscale),
        media: req.media.unwrap_or(MediaSize::Letter),
    };

    let svc_req = pf_job_queue::SubmitJobRequest {
        document_name: req.document_name,
        options,
        cost_center,
        page_count: None,
    };

    let job = svc.submit_job(identity, svc_req).await.map_err(|e| {
        match e {
            pf_job_queue::JobQueueError::Validation(_) => {
                ApiError::bad_request(Uuid::now_v7(), e.to_string())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(SubmitJobResponse {
        job_id: job.id,
        status: job.status,
        submitted_at: job.submitted_at,
    }))
}

/// List jobs for the authenticated user with optional status filter.
///
/// **NIST 800-53 Rev 5:** AC-3 — scoped to the authenticated user.
///
/// # Errors
///
/// Returns `ApiError` on internal error.
async fn list_jobs(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Query(_params): Query<ListJobsQuery>,
) -> Result<Json<ListJobsResponse>, ApiError> {
    let svc = state.job_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let summaries = svc.list_jobs(identity).await.map_err(|e| {
        ApiError::internal(Uuid::now_v7(), e)
    })?;

    let jobs = summaries
        .into_iter()
        .map(|s| JobSummary {
            id: s.id,
            document_name: s.document_name,
            status: s.status,
            submitted_at: s.submitted_at,
            page_count: s.page_count,
        })
        .collect();

    Ok(Json(ListJobsResponse {
        jobs,
        total: 0, // Total count requires a separate count query; using 0 for now.
    }))
}

/// Get details of a specific job.
///
/// **NIST 800-53 Rev 5:** AC-3 — user must own the job or be an admin.
///
/// # Errors
///
/// Returns `ApiError::not_found` if the job does not exist.
async fn get_job(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<JobDetailResponse>, ApiError> {
    let parsed_id = Uuid::parse_str(&id)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid job ID format"))?;

    let svc = state.job_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let job_id = JobId::new(parsed_id)
        .map_err(|e| ApiError::bad_request(Uuid::now_v7(), e.to_string()))?;
    let job = svc.get_job(identity, job_id).await.map_err(|e| {
        match e {
            pf_job_queue::JobQueueError::NotFound => ApiError::not_found(Uuid::now_v7()),
            pf_job_queue::JobQueueError::Unauthorized => ApiError::forbidden(Uuid::now_v7()),
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(JobDetailResponse {
        id: job.id,
        document_name: job.document_name,
        status: job.status,
        options: job.options,
        cost_center: job.cost_center,
        page_count: job.page_count,
        submitted_at: job.submitted_at,
        released_at: job.released_at,
        completed_at: job.completed_at,
    }))
}

/// Release a held job to a target printer.
///
/// **NIST 800-53 Rev 5:** AC-3 — user must own the job.
///
/// # Errors
///
/// Returns `ApiError` if the job is not in `Held` status or does not exist.
async fn release_job(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<String>,
    Json(req): Json<ReleaseJobRequest>,
) -> Result<Json<ReleaseJobResponse>, ApiError> {
    let parsed_id = Uuid::parse_str(&id)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid job ID format"))?;

    let svc = state.job_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let job_id = JobId::new(parsed_id)
        .map_err(|e| ApiError::bad_request(Uuid::now_v7(), e.to_string()))?;
    let printer_id = PrinterId::new(&req.printer_id)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid printer ID format"))?;

    let job = svc.release_job(identity, job_id, printer_id).await.map_err(|e| {
        match e {
            pf_job_queue::JobQueueError::NotFound => ApiError::not_found(Uuid::now_v7()),
            pf_job_queue::JobQueueError::Unauthorized => ApiError::forbidden(Uuid::now_v7()),
            pf_job_queue::JobQueueError::InvalidTransition { .. } => {
                ApiError::bad_request(Uuid::now_v7(), e.to_string())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(ReleaseJobResponse {
        job_id: job.id,
        status: job.status,
        printer_id: req.printer_id,
    }))
}

/// Cancel a held job.
///
/// **NIST 800-53 Rev 5:** AC-3 — user must own the job or be an admin.
///
/// # Errors
///
/// Returns `ApiError` if the job is not in a cancellable state.
async fn cancel_job(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<CancelJobResponse>, ApiError> {
    let parsed_id = Uuid::parse_str(&id)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid job ID format"))?;

    let svc = state.job_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let job_id = JobId::new(parsed_id)
        .map_err(|e| ApiError::bad_request(Uuid::now_v7(), e.to_string()))?;
    svc.cancel_job(identity, job_id.clone()).await.map_err(|e| {
        match e {
            pf_job_queue::JobQueueError::NotFound => ApiError::not_found(Uuid::now_v7()),
            pf_job_queue::JobQueueError::Unauthorized => ApiError::forbidden(Uuid::now_v7()),
            pf_job_queue::JobQueueError::InvalidTransition { .. } => {
                ApiError::bad_request(Uuid::now_v7(), e.to_string())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(CancelJobResponse {
        job_id,
        status: JobStatus::Purged,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_job_request_deserializes() {
        let json = r#"{
            "document_name": "test.pdf",
            "copies": 2,
            "cost_center_code": "CC-001",
            "cost_center_name": "Test"
        }"#;
        let req: SubmitJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.document_name, "test.pdf");
        assert_eq!(req.copies, Some(2));
    }

    #[test]
    fn list_jobs_query_defaults() {
        let json = "{}";
        let query: ListJobsQuery = serde_json::from_str(json).unwrap();
        assert!(query.status.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn release_job_request_deserializes() {
        let json = r#"{"printer_id": "PRN-0042"}"#;
        let req: ReleaseJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.printer_id, "PRN-0042");
    }
}
