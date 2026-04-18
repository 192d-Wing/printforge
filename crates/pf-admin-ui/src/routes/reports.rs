// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Report generation route handlers.
//!
//! Report generation is asynchronous: [`generate_report`] persists a
//! `Pending` row via [`ReportService::enqueue`](pf_reports::ReportService::enqueue)
//! and returns the id immediately so the request thread is never blocked on
//! artifact generation. The SPA polls [`get_report`] for status transitions
//! (`Pending → Generating → Ready` | `Failed`). A worker process (separate
//! slice) consumes Pending rows and writes artifacts to object storage.
//!
//! **NIST 800-53 Rev 5:** AU-2, AU-12 — Report generation and export are
//! auditable events.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use pf_auth::middleware::RequireAuth;
use pf_reports::{NewReport, ReportError, ReportFormat, ReportKind, ReportRecord};

use crate::error::AdminUiError;
use crate::reports::{
    ReportFormat as WireFormat, ReportKind as WireKind, ReportMetadata, ReportRequest,
};
use crate::scope::derive_scope;
use crate::state::AdminState;

/// Build the `/reports` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/generate", post(generate_report))
        .route("/{id}", get(get_report))
}

/// `POST /reports/generate` — Enqueue a report for asynchronous generation.
///
/// Returns `202-equivalent` metadata immediately: the record is in
/// [`ReportState::Pending`](pf_reports::ReportState) with `row_count = 0`.
/// The caller polls `GET /reports/{id}` for status transitions.
///
/// If the requester passes a `site_id`, the handler enforces that the site
/// is within the caller's scope. A Fleet Admin may request any site (or all
/// sites by omitting `site_id`); a Site Admin is restricted to their
/// authorized sites.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, AU-12 — Report
/// generation is an auditable event.
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` — caller lacks an admin role.
/// - `AdminUiError::ScopeViolation` — requested site is outside scope.
/// - `AdminUiError::ServiceUnavailable` — report service not wired.
/// - `AdminUiError::Internal` — underlying service failure.
async fn generate_report(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
    Json(request): Json<ReportRequest>,
) -> Result<Json<ReportMetadata>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let reports_svc = state
        .reports
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "reports" })?;

    if let Some(ref site) = request.site_id {
        crate::scope::require_site_access(&scope, site)?;
    }

    let record = reports_svc
        .enqueue(NewReport {
            kind: map_kind(request.kind),
            format: map_format(request.format),
            requested_by: identity.edipi.as_str().to_string(),
            site_id: request.site_id.map(|s| s.0).unwrap_or_default(),
            start_date: request.start_date,
            end_date: request.end_date,
        })
        .await
        .map_err(map_report_error)?;

    tracing::info!(
        report_id = %record.id,
        kind = ?record.kind,
        requested_by = %record.requested_by,
        "report generation enqueued"
    );

    Ok(Json(to_report_metadata(&record)))
}

/// `GET /reports/{id}` — Retrieve a previously-enqueued report.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` — caller lacks an admin role.
/// - `AdminUiError::NotFound` — no report with the given id (or the id is
///   not a valid UUID).
/// - `AdminUiError::ServiceUnavailable` — report service not wired.
/// - `AdminUiError::Internal` — underlying service failure.
async fn get_report(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
    Path(id_str): Path<String>,
) -> Result<Json<ReportMetadata>, AdminUiError> {
    let _scope = derive_scope(&identity.roles)?;
    let reports_svc = state
        .reports
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "reports" })?;

    let id = Uuid::parse_str(&id_str).map_err(|_| AdminUiError::NotFound {
        entity: format!("report {id_str}"),
    })?;

    let record = reports_svc.get(id).await.map_err(map_report_error)?;
    Ok(Json(to_report_metadata(&record)))
}

fn map_kind(k: WireKind) -> ReportKind {
    match k {
        WireKind::Chargeback => ReportKind::Chargeback,
        WireKind::Utilization => ReportKind::Utilization,
        WireKind::QuotaCompliance => ReportKind::QuotaCompliance,
        WireKind::WasteReduction => ReportKind::WasteReduction,
    }
}

fn map_format(f: WireFormat) -> ReportFormat {
    match f {
        WireFormat::Json => ReportFormat::Json,
        WireFormat::Csv => ReportFormat::Csv,
    }
}

fn unmap_kind(k: ReportKind) -> WireKind {
    match k {
        ReportKind::Chargeback => WireKind::Chargeback,
        ReportKind::Utilization => WireKind::Utilization,
        ReportKind::QuotaCompliance => WireKind::QuotaCompliance,
        ReportKind::WasteReduction => WireKind::WasteReduction,
    }
}

/// Map a persisted [`ReportRecord`] onto the admin-ui wire type.
///
/// `generated_at` on the wire type reflects either the completion time
/// (once the worker finishes) or the request time for Pending rows — the
/// SPA treats it as "most recent state transition". `row_count` is 0 until
/// the report reaches `Ready`.
fn to_report_metadata(r: &ReportRecord) -> ReportMetadata {
    ReportMetadata {
        report_id: r.id.to_string(),
        kind: unmap_kind(r.kind),
        generated_at: r.completed_at.unwrap_or(r.requested_at),
        start_date: r.start_date,
        end_date: r.end_date,
        row_count: r.row_count.unwrap_or(0),
    }
}

/// Map a [`ReportError`] onto the admin-ui error type.
fn map_report_error(err: ReportError) -> AdminUiError {
    match err {
        ReportError::NotFound => AdminUiError::NotFound {
            entity: "report".to_string(),
        },
        ReportError::InvalidPeriod { reason } => AdminUiError::ReportGeneration { reason },
        ReportError::Repository(_) => AdminUiError::Internal {
            source: Box::new(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Utc};
    use pf_reports::ReportState;

    fn sample_record(state: ReportState) -> ReportRecord {
        ReportRecord {
            id: Uuid::now_v7(),
            kind: ReportKind::Chargeback,
            format: ReportFormat::Csv,
            requested_by: "1234567890".to_string(),
            requested_at: Utc::now(),
            site_id: "langley".to_string(),
            start_date: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
            state,
            row_count: None,
            output_location: None,
            failure_reason: None,
            completed_at: None,
        }
    }

    #[test]
    fn kind_roundtrip() {
        for k in [
            WireKind::Chargeback,
            WireKind::Utilization,
            WireKind::QuotaCompliance,
            WireKind::WasteReduction,
        ] {
            assert_eq!(unmap_kind(map_kind(k)), k);
        }
    }

    #[test]
    fn format_maps_both_variants() {
        assert_eq!(map_format(WireFormat::Json), ReportFormat::Json);
        assert_eq!(map_format(WireFormat::Csv), ReportFormat::Csv);
    }

    #[test]
    fn to_report_metadata_pending_reports_zero_rows() {
        let record = sample_record(ReportState::Pending);
        let expected_generated_at = record.requested_at;
        let meta = to_report_metadata(&record);
        assert_eq!(meta.row_count, 0);
        assert_eq!(meta.generated_at, expected_generated_at);
    }

    #[test]
    fn to_report_metadata_ready_reports_row_count_and_completed_at() {
        let mut record = sample_record(ReportState::Ready);
        record.row_count = Some(42);
        record.completed_at = Some(Utc::now());
        let expected_generated_at = record.completed_at.unwrap();
        let meta = to_report_metadata(&record);
        assert_eq!(meta.row_count, 42);
        assert_eq!(meta.generated_at, expected_generated_at);
    }

    #[test]
    fn map_report_error_not_found_becomes_admin_not_found() {
        let mapped = map_report_error(ReportError::NotFound);
        assert!(matches!(mapped, AdminUiError::NotFound { .. }));
    }

    #[test]
    fn map_report_error_invalid_period_becomes_report_generation() {
        let err = ReportError::InvalidPeriod {
            reason: "start after end".to_string(),
        };
        let mapped = map_report_error(err);
        assert!(matches!(mapped, AdminUiError::ReportGeneration { .. }));
    }

    #[test]
    fn report_metadata_serialization_roundtrip() {
        let meta = to_report_metadata(&sample_record(ReportState::Pending));
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: ReportMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.row_count, 0);
    }
}
