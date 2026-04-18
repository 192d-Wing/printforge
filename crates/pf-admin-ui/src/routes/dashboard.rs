// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Dashboard KPI route handlers.
//!
//! Composes aggregates from [`FleetService`], [`JobService`], and
//! [`AccountingService`] into a single [`DashboardKpis`] snapshot. All three
//! sources honor the caller's site scope — a Fleet Admin sees global
//! numbers; a Site Admin for Langley sees only Langley rows.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{Datelike, NaiveDate, Utc};

use pf_auth::middleware::RequireAuth;
use pf_common::identity::Role;
use pf_fleet_mgr::AlertState;

use crate::dashboard::DashboardKpis;
use crate::error::AdminUiError;
use crate::scope::{derive_scope, scope_to_installations};
use crate::state::AdminState;

/// Build the `/dashboard` router.
pub fn router() -> Router<AdminState> {
    Router::new().route("/kpis", get(get_kpis))
}

/// `GET /dashboard/kpis` — Return aggregated dashboard KPIs scoped to the
/// caller's authorized sites.
///
/// Runs three service calls: fleet status summary, job status counts, and
/// the current-month accounting totals. If any backend service is not wired
/// on [`AdminState`], returns `AdminUiError::ServiceUnavailable`.
///
/// `active_alerts` is reported as `0` for now — a dedicated
/// `AlertService` is a later slice; rather than guess, we surface zero and
/// let the SPA show "—" until alerts are wired.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` if the caller lacks an admin role.
/// - `AdminUiError::ServiceUnavailable` if any backend is not wired.
/// - `AdminUiError::Internal` on underlying service failure.
async fn get_kpis(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<DashboardKpis>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let installations = scope_to_installations(&scope);

    let fleet = state
        .fleet
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "fleet" })?;
    let jobs = state
        .jobs
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "jobs" })?;
    let accounting = state
        .accounting
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable {
            service: "accounting",
        })?;

    let fleet_counts = fleet
        .status_summary(installations.clone())
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    let job_counts = jobs
        .count_by_status(installations.clone())
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    let now = Utc::now();
    let (start, end) = current_month_range(now.date_naive());
    let totals = accounting
        .monthly_totals(installations.clone(), start, end)
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    // Active alert count is best-effort: if the AlertService handle isn't
    // wired we report 0 rather than 503 the whole dashboard. A missing
    // fleet/jobs/accounting handle DOES 503 because those numbers would be
    // misleading; a missing alert count is obvious (zero).
    let active_alerts = match state.alerts.as_ref() {
        Some(svc) => {
            svc.list_scoped(installations, Some(AlertState::Active), 1, 0)
                .await
                .map(|(_, total)| total)
                .map_err(|e| AdminUiError::Internal {
                    source: Box::new(e),
                })?
        }
        None => 0,
    };

    let total_printers = fleet_counts.online
        + fleet_counts.offline
        + fleet_counts.error
        + fleet_counts.maintenance
        + fleet_counts.printing;

    let active_jobs = job_counts.waiting + job_counts.releasing + job_counts.printing;

    Ok(Json(DashboardKpis {
        computed_at: now,
        total_printers,
        online_printers: fleet_counts.online,
        error_printers: fleet_counts.error,
        maintenance_printers: fleet_counts.maintenance,
        held_jobs: job_counts.held,
        active_jobs,
        monthly_pages: totals.pages,
        monthly_cost_cents: totals.cost_cents,
        active_alerts,
    }))
}

/// Return `(start_of_month, end_of_month)` for the calendar month that
/// contains `today`.
///
/// `end_of_month` is inclusive — the last day of the month. February is
/// handled correctly (28 or 29 days); December rolls `year + 1` for the
/// boundary arithmetic.
fn current_month_range(today: NaiveDate) -> (NaiveDate, NaiveDate) {
    let start = NaiveDate::from_ymd_opt(today.year(), today.month(), 1)
        .expect("first day of current month is always a valid date");

    let (ny, nm) = if today.month() == 12 {
        (today.year() + 1, 1)
    } else {
        (today.year(), today.month() + 1)
    };
    let end = NaiveDate::from_ymd_opt(ny, nm, 1)
        .expect("first day of next month is always a valid date")
        .pred_opt()
        .expect("day before first-of-next-month is always valid");

    (start, end)
}

/// Admin roles required to read KPIs. Only Fleet Admin and Site Admin
/// have dashboard access; non-admin `Role::User` is rejected upstream by
/// [`derive_scope`], and `Role::Auditor` currently gets read-only global
/// access. This helper is not used yet; kept for future per-widget gating.
#[allow(dead_code)]
fn is_admin_role(role: &Role) -> bool {
    matches!(role, Role::FleetAdmin | Role::SiteAdmin(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::DashboardKpis;

    #[test]
    fn current_month_range_boundaries_inside_month() {
        let (start, end) = current_month_range(NaiveDate::from_ymd_opt(2026, 3, 15).unwrap());
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 3, 1).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 3, 31).unwrap());
    }

    #[test]
    fn current_month_range_handles_february_leap() {
        let (start, end) = current_month_range(NaiveDate::from_ymd_opt(2024, 2, 10).unwrap());
        assert_eq!(start, NaiveDate::from_ymd_opt(2024, 2, 1).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2024, 2, 29).unwrap());
    }

    #[test]
    fn current_month_range_handles_february_non_leap() {
        let (start, end) = current_month_range(NaiveDate::from_ymd_opt(2026, 2, 10).unwrap());
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 2, 1).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 2, 28).unwrap());
    }

    #[test]
    fn current_month_range_handles_december_rollover() {
        let (start, end) = current_month_range(NaiveDate::from_ymd_opt(2026, 12, 15).unwrap());
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 12, 1).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 12, 31).unwrap());
    }

    #[test]
    fn dashboard_kpis_response_serializes() {
        let kpis = DashboardKpis {
            computed_at: Utc::now(),
            total_printers: 42,
            online_printers: 38,
            error_printers: 2,
            maintenance_printers: 2,
            held_jobs: 15,
            active_jobs: 3,
            monthly_pages: 10_000,
            monthly_cost_cents: 25_000,
            active_alerts: 0,
        };
        let json = serde_json::to_string(&kpis).unwrap();
        assert!(json.contains("\"total_printers\":42"));
        assert!(json.contains("\"active_alerts\":0"));
    }
}
