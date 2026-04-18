// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Alert feed route handlers.
//!
//! **NIST 800-53 Rev 5:** SI-4 — Information System Monitoring

use axum::extract::Path;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use uuid::Uuid;

use pf_auth::middleware::RequireAuth;
use pf_common::identity::SiteId;

use crate::alerts::{
    Alert, AlertCategory, AlertListResponse, AlertSeverity, AlertState,
};
use crate::error::AdminUiError;
use crate::scope::{derive_scope, DataScope};
use crate::state::AdminState;

/// Build the `/alerts` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/", get(list_alerts))
        .route("/{id}/acknowledge", post(acknowledge_alert))
}

/// Build stub alert data scoped to the requester's authorized sites.
fn stub_alerts(scope: &DataScope) -> Vec<Alert> {
    let all_alerts = vec![
        Alert {
            alert_id: Uuid::now_v7(),
            severity: AlertSeverity::Critical,
            category: AlertCategory::PrinterStatus,
            state: AlertState::Active,
            title: "Printer PRN-0042 offline".to_string(),
            description: "Printer has not responded to SNMPv3 polls for 10 minutes."
                .to_string(),
            site_id: SiteId("langley".to_string()),
            printer_id: Some(
                pf_common::fleet::PrinterId::new("PRN-0042")
                    .expect("valid stub printer ID"),
            ),
            created_at: Utc::now(),
            acknowledged_at: None,
            acknowledged_by: None,
            resolved_at: None,
        },
        Alert {
            alert_id: Uuid::now_v7(),
            severity: AlertSeverity::Warning,
            category: AlertCategory::SupplyLow,
            state: AlertState::Active,
            title: "Low toner on PRN-0099".to_string(),
            description: "Black toner is at 5%.".to_string(),
            site_id: SiteId("ramstein".to_string()),
            printer_id: Some(
                pf_common::fleet::PrinterId::new("PRN-0099")
                    .expect("valid stub printer ID"),
            ),
            created_at: Utc::now(),
            acknowledged_at: None,
            acknowledged_by: None,
            resolved_at: None,
        },
    ];

    match scope {
        DataScope::Global => all_alerts,
        DataScope::Sites(sites) => all_alerts
            .into_iter()
            .filter(|a| sites.contains(&a.site_id))
            .collect(),
    }
}

/// `GET /alerts` — List active alerts scoped to the requester's sites.
///
/// **NIST 800-53 Rev 5:** SI-4 — Information System Monitoring
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester lacks admin access.
async fn list_alerts(
    RequireAuth(identity): RequireAuth,
) -> Result<Json<AlertListResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let alerts = stub_alerts(&scope);
    let total_count = alerts.len() as u64;

    Ok(Json(AlertListResponse {
        alerts,
        total_count,
        page: 1,
        page_size: 25,
    }))
}

/// `POST /alerts/{id}/acknowledge` — Acknowledge an active alert.
///
/// **NIST 800-53 Rev 5:** SI-4 — Acknowledgment is an auditable event.
///
/// # Errors
///
/// Returns `AdminUiError::NotFound` if the alert does not exist.
async fn acknowledge_alert(
    RequireAuth(_identity): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<Alert>, AdminUiError> {
    let alert_id = Uuid::parse_str(&id).map_err(|_| AdminUiError::NotFound {
        entity: format!("alert {id}"),
    })?;

    // Stub: return an acknowledged alert.
    Ok(Json(Alert {
        alert_id,
        severity: AlertSeverity::Critical,
        category: AlertCategory::PrinterStatus,
        state: AlertState::Acknowledged,
        title: "Printer PRN-0042 offline".to_string(),
        description: "Printer has not responded to SNMPv3 polls for 10 minutes."
            .to_string(),
        site_id: SiteId("langley".to_string()),
        printer_id: Some(
            pf_common::fleet::PrinterId::new("PRN-0042")
                .expect("valid stub printer ID"),
        ),
        created_at: Utc::now(),
        acknowledged_at: Some(Utc::now()),
        acknowledged_by: Some("DOE, JOHN Q.".to_string()),
        resolved_at: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::identity::Role;

    #[test]
    fn nist_si4_alert_list_response_serializes() {
        // NIST 800-53 Rev 5: SI-4 — Information System Monitoring
        // Evidence: Alert list response serializes correctly for dashboard.
        let scope = DataScope::Global;
        let alerts = stub_alerts(&scope);
        let response = AlertListResponse {
            total_count: alerts.len() as u64,
            alerts,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("PrinterStatus"));
        assert!(json.contains("langley"));
    }

    #[test]
    fn nist_ac3_site_admin_only_sees_own_site_alerts() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Site admin for langley does not see ramstein alerts.
        let scope = DataScope::Sites(vec![SiteId("langley".to_string())]);
        let alerts = stub_alerts(&scope);
        assert!(alerts
            .iter()
            .all(|a| a.site_id == SiteId("langley".to_string())));
        assert!(!alerts.is_empty());
    }

    #[test]
    fn nist_ac3_fleet_admin_sees_all_alerts() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Fleet admin sees alerts from all sites.
        let roles = vec![Role::FleetAdmin];
        let scope = derive_scope(&roles).unwrap();
        let alerts = stub_alerts(&scope);
        let sites: Vec<&SiteId> = alerts.iter().map(|a| &a.site_id).collect();
        assert!(sites.contains(&&SiteId("langley".to_string())));
        assert!(sites.contains(&&SiteId("ramstein".to_string())));
    }
}
