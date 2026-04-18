// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Report generation route handlers.
//!
//! **NIST 800-53 Rev 5:** AU-2, AU-12 — Report generation and export are
//! auditable events.

use axum::extract::Path;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;

use pf_auth::middleware::RequireAuth;

use crate::error::AdminUiError;
use crate::reports::{ReportMetadata, ReportRequest};
use crate::scope::derive_scope;
use crate::state::AdminState;

/// Build the `/reports` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/generate", post(generate_report))
        .route("/{id}", get(get_report))
}

/// `POST /reports/generate` — Generate a report for the given parameters.
///
/// The report is scoped to the requester's authorized sites.
///
/// **NIST 800-53 Rev 5:** AU-12 — Report generation is an auditable event.
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester does not hold
/// an admin-level role. Returns `AdminUiError::ScopeViolation` if the
/// requested site is outside the requester's scope.
async fn generate_report(
    RequireAuth(identity): RequireAuth,
    Json(request): Json<ReportRequest>,
) -> Result<Json<ReportMetadata>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;

    // Enforce site scope if a specific site was requested.
    if let Some(ref site_id) = request.site_id {
        crate::scope::require_site_access(&scope, site_id)?;
    }

    tracing::info!(
        kind = ?request.kind,
        format = ?request.format,
        "report generation requested"
    );

    // Stub: return placeholder report metadata.
    Ok(Json(ReportMetadata {
        report_id: uuid::Uuid::now_v7().to_string(),
        kind: request.kind,
        generated_at: Utc::now(),
        start_date: request.start_date,
        end_date: request.end_date,
        row_count: 0,
    }))
}

/// `GET /reports/{id}` — Retrieve a previously generated report by ID.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns `AdminUiError::NotFound` if the report does not exist.
async fn get_report(
    RequireAuth(_identity): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<ReportMetadata>, AdminUiError> {
    // Stub: report lookup not yet implemented.
    Err(AdminUiError::NotFound {
        entity: format!("report {id}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::ReportKind;
    use chrono::NaiveDate;

    #[test]
    fn report_metadata_serialization_roundtrip() {
        let meta = ReportMetadata {
            report_id: "test-001".to_string(),
            kind: ReportKind::Chargeback,
            generated_at: Utc::now(),
            start_date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 1, 31).unwrap(),
            row_count: 42,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: ReportMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.report_id, "test-001");
        assert_eq!(deserialized.row_count, 42);
    }
}
