// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Accounting routes: quota status and chargeback reporting.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{RequireAuth, is_admin};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Current quota status for a user.
#[derive(Debug, Serialize)]
pub struct QuotaStatusResponse {
    /// The user's EDIPI (caller).
    pub edipi: String,
    /// Monthly page quota.
    pub monthly_quota: u64,
    /// Pages used this month.
    pub pages_used: u64,
    /// Pages remaining.
    pub pages_remaining: u64,
    /// Quota reset date.
    pub resets_at: DateTime<Utc>,
}

/// Query parameters for the chargeback report.
#[derive(Debug, Deserialize)]
pub struct ChargebackQuery {
    /// Start of the reporting period.
    pub from: Option<DateTime<Utc>>,
    /// End of the reporting period.
    pub to: Option<DateTime<Utc>>,
    /// Filter by cost-center code.
    pub cost_center: Option<String>,
}

/// A single line item in a chargeback report.
#[derive(Debug, Serialize)]
pub struct ChargebackLineItem {
    /// Cost-center code.
    pub cost_center_code: String,
    /// Cost-center display name.
    pub cost_center_name: String,
    /// Total pages printed.
    pub total_pages: u64,
    /// Total cost in cents.
    pub total_cost_cents: u64,
    /// Number of jobs.
    pub job_count: u64,
}

/// Response for the chargeback report.
#[derive(Debug, Serialize)]
pub struct ChargebackReportResponse {
    /// Start of the reporting period.
    pub from: DateTime<Utc>,
    /// End of the reporting period.
    pub to: DateTime<Utc>,
    /// Line items grouped by cost center.
    pub line_items: Vec<ChargebackLineItem>,
    /// Grand total cost in cents.
    pub grand_total_cents: u64,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the `/accounting` router.
///
/// - `GET /quota` — available to all authenticated users.
/// - `GET /reports/chargeback` — admin only.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/quota", get(get_quota))
        .route("/reports/chargeback", get(get_chargeback_report))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Get the current user's print quota status.
///
/// **NIST 800-53 Rev 5:** AC-3 — requires authenticated user.
///
/// # Errors
///
/// Returns `ApiError` on internal error.
async fn get_quota(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<QuotaStatusResponse>, ApiError> {
    let svc = state.accounting_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let status = svc.get_quota_status(identity.edipi).await.map_err(|e| {
        ApiError::internal(Uuid::now_v7(), e)
    })?;

    Ok(Json(QuotaStatusResponse {
        edipi: status.edipi.as_str().to_string(),
        monthly_quota: u64::from(status.page_limit),
        pages_used: u64::from(status.pages_used),
        pages_remaining: u64::from(status.pages_remaining),
        resets_at: status.period_end,
    }))
}

/// Generate a chargeback report (admin only).
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement (admin required).
///
/// # Errors
///
/// Returns `ApiError::forbidden` if the caller is not an admin.
async fn get_chargeback_report(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Query(params): Query<ChargebackQuery>,
) -> Result<Json<ChargebackReportResponse>, ApiError> {
    if !is_admin(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let svc = state.accounting_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let now = Utc::now();
    let from_dt = params.from.unwrap_or(now - chrono::Duration::days(30));
    let to_dt = params.to.unwrap_or(now);

    let from_date = from_dt.date_naive();
    let to_date = to_dt.date_naive();

    let cost_center_filter = params.cost_center.as_ref().map(|code| {
        pf_common::job::CostCenter::new(code, code)
            .unwrap_or_else(|_| pf_common::job::CostCenter::new("ALL", "All Cost Centers")
                .expect("static cost center values are valid"))
    });

    let report = svc.get_chargeback_report(
        from_date,
        to_date,
        cost_center_filter,
    ).await.map_err(|e| {
        match e {
            pf_accounting::AccountingError::InvalidChargebackPeriod { .. } => {
                ApiError::bad_request(Uuid::now_v7(), e.to_string())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(ChargebackReportResponse {
        from: from_dt,
        to: to_dt,
        line_items: vec![ChargebackLineItem {
            cost_center_code: report.cost_center.code.clone(),
            cost_center_name: report.cost_center.name.clone(),
            total_pages: u64::from(report.total_impressions),
            total_cost_cents: report.total_cost_cents,
            job_count: u64::from(report.total_jobs),
        }],
        grand_total_cents: report.total_cost_cents,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chargeback_query_defaults() {
        let json = "{}";
        let query: ChargebackQuery = serde_json::from_str(json).unwrap();
        assert!(query.from.is_none());
        assert!(query.cost_center.is_none());
    }

    #[test]
    fn chargeback_line_item_serializes() {
        let item = ChargebackLineItem {
            cost_center_code: "CC-001".to_string(),
            cost_center_name: "Test".to_string(),
            total_pages: 100,
            total_cost_cents: 500,
            job_count: 10,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("CC-001"));
    }
}
