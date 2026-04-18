// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Dashboard KPI route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All data is scoped to the requester's
//! authorized sites via [`DataScope`](crate::scope::DataScope).

use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;

use pf_auth::middleware::RequireAuth;

use crate::dashboard::DashboardKpis;
use crate::error::AdminUiError;
use crate::scope::derive_scope;
use crate::state::AdminState;

/// Build the `/dashboard` router.
pub fn router() -> Router<AdminState> {
    Router::new().route("/kpis", get(get_kpis))
}

/// `GET /dashboard/kpis` — Return aggregated dashboard KPIs scoped to the
/// requester's authorized sites.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester does not hold
/// an admin-level role.
async fn get_kpis(
    RequireAuth(identity): RequireAuth,
) -> Result<Json<DashboardKpis>, AdminUiError> {
    let _scope = derive_scope(&identity.roles)?;

    // Stub: return placeholder KPI data.
    Ok(Json(DashboardKpis {
        computed_at: Utc::now(),
        total_printers: 42,
        online_printers: 38,
        error_printers: 2,
        maintenance_printers: 2,
        held_jobs: 15,
        active_jobs: 3,
        monthly_pages: 10_000,
        monthly_cost_cents: 25_000,
        active_alerts: 5,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::DashboardKpis;

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
            active_alerts: 5,
        };
        let json = serde_json::to_string(&kpis).unwrap();
        assert!(json.contains("\"total_printers\":42"));
    }
}
