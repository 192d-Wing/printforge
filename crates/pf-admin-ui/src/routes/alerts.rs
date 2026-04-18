// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Alert feed route handlers.
//!
//! **NIST 800-53 Rev 5:** SI-4 — Information System Monitoring

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use pf_auth::middleware::RequireAuth;
use pf_common::identity::SiteId;
use pf_fleet_mgr::{
    AlertCategory as FleetCategory, AlertSeverity as FleetSeverity, AlertState as FleetState,
    StoredAlert,
};

use crate::alerts::{
    Alert, AlertCategory, AlertListResponse, AlertSeverity, AlertState,
};
use crate::error::AdminUiError;
use crate::scope::{derive_scope, require_site_access, scope_to_installations};
use crate::state::AdminState;

/// Default page size when the client does not specify one.
const DEFAULT_PAGE_SIZE: u32 = 25;

/// Build the `/alerts` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/", get(list_alerts))
        .route("/{id}/acknowledge", post(acknowledge_alert))
}

/// `GET /alerts` — List active alerts scoped to the caller's sites.
///
/// Backed by [`AlertService::list_scoped`](pf_fleet_mgr::AlertService::list_scoped).
///
/// **NIST 800-53 Rev 5:** SI-4 — System Monitoring, AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` — caller lacks an admin role.
/// - `AdminUiError::ServiceUnavailable` — alert service not wired.
/// - `AdminUiError::Internal` — underlying service failure.
async fn list_alerts(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<AlertListResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let alerts_svc = state
        .alerts
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "alerts" })?;

    let (page, total_count) = alerts_svc
        .list_scoped(
            scope_to_installations(&scope),
            Some(FleetState::Active),
            DEFAULT_PAGE_SIZE,
            0,
        )
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    let alerts = page.into_iter().map(to_admin_alert).collect();

    Ok(Json(AlertListResponse {
        alerts,
        total_count,
        page: 1,
        page_size: DEFAULT_PAGE_SIZE,
    }))
}

/// `POST /alerts/{id}/acknowledge` — Mark an active alert as acknowledged.
///
/// A Site Admin may only acknowledge alerts at one of their authorized
/// sites; the handler fetches the alert first and applies scope enforcement
/// before the mutation. `acknowledged_by` is populated from the caller's
/// EDIPI; the SPA can resolve to a display name via the users endpoint.
///
/// **NIST 800-53 Rev 5:** SI-4 — Acknowledgment is an auditable event;
/// AC-3 — Access Enforcement.
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` — caller lacks an admin role.
/// - `AdminUiError::ScopeViolation` — alert is outside the caller's sites.
/// - `AdminUiError::NotFound` — no alert exists with the given ID.
/// - `AdminUiError::ServiceUnavailable` — alert service not wired.
/// - `AdminUiError::Internal` — underlying service failure.
async fn acknowledge_alert(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
    Path(id_str): Path<String>,
) -> Result<Json<Alert>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let alerts_svc = state
        .alerts
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "alerts" })?;

    let alert_id = Uuid::parse_str(&id_str).map_err(|_| AdminUiError::NotFound {
        entity: format!("alert {id_str}"),
    })?;

    // Fetch first so scope enforcement runs before any mutation.
    let existing = alerts_svc
        .get_by_id(alert_id)
        .await
        .map_err(map_alert_error)?;
    if !existing.site_id.is_empty() {
        require_site_access(&scope, &SiteId(existing.site_id.clone()))?;
    }

    let acked = alerts_svc
        .acknowledge(alert_id, identity.edipi.as_str().to_string())
        .await
        .map_err(map_alert_error)?;

    tracing::info!(
        caller = %identity.edipi,
        alert_id = %alert_id,
        "alert acknowledged"
    );

    Ok(Json(to_admin_alert(acked)))
}

/// Map a [`pf_fleet_mgr::FleetError`] onto the admin-ui error type.
fn map_alert_error(err: pf_fleet_mgr::FleetError) -> AdminUiError {
    if matches!(err, pf_fleet_mgr::FleetError::PrinterNotFound) {
        // AlertRepository reuses the PrinterNotFound variant when an alert
        // ID is unknown; see pf-fleet-mgr::alert_store docs.
        AdminUiError::NotFound {
            entity: "alert".to_string(),
        }
    } else {
        AdminUiError::Internal {
            source: Box::new(err),
        }
    }
}

/// Map the fleet-mgr [`StoredAlert`] onto the admin-ui wire type.
fn to_admin_alert(s: StoredAlert) -> Alert {
    Alert {
        alert_id: s.id,
        severity: map_severity(s.severity),
        category: map_category(s.category),
        state: map_state(s.state),
        title: s.summary,
        description: s.detail.unwrap_or_default(),
        site_id: SiteId(s.site_id),
        printer_id: Some(s.printer_id),
        created_at: s.generated_at,
        acknowledged_at: s.acknowledged_at,
        acknowledged_by: s.acknowledged_by,
        resolved_at: s.resolved_at,
    }
}

fn map_severity(s: FleetSeverity) -> AlertSeverity {
    match s {
        FleetSeverity::Info => AlertSeverity::Info,
        FleetSeverity::Warning => AlertSeverity::Warning,
        FleetSeverity::Critical => AlertSeverity::Critical,
    }
}

fn map_state(s: FleetState) -> AlertState {
    match s {
        FleetState::Active => AlertState::Active,
        FleetState::Acknowledged => AlertState::Acknowledged,
        FleetState::Resolved => AlertState::Resolved,
    }
}

/// Fold fleet-mgr's fine-grained categories into the admin-ui's coarser
/// buckets suitable for dashboard grouping.
fn map_category(c: FleetCategory) -> AlertCategory {
    match c {
        FleetCategory::PrinterOffline
        | FleetCategory::PrinterError
        | FleetCategory::HealthDegraded => AlertCategory::PrinterStatus,
        FleetCategory::TonerLow | FleetCategory::PaperLow => AlertCategory::SupplyLow,
        FleetCategory::FirmwareOutdated => AlertCategory::Firmware,
        FleetCategory::StigViolation => AlertCategory::Security,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pf_common::fleet::PrinterId;
    use pf_fleet_mgr::{AlertCategory as FleetCategory, AlertSeverity as FleetSeverity};

    fn sample(site: &str, category: FleetCategory) -> StoredAlert {
        StoredAlert {
            id: Uuid::new_v4(),
            printer_id: PrinterId::new("PRN-0001").unwrap(),
            site_id: site.to_string(),
            severity: FleetSeverity::Critical,
            category,
            state: FleetState::Active,
            summary: "Test alert".to_string(),
            detail: Some("Extra detail".to_string()),
            generated_at: Utc::now(),
            acknowledged_at: None,
            acknowledged_by: None,
            resolved_at: None,
        }
    }

    #[test]
    fn to_admin_alert_maps_site_id_and_printer() {
        let mapped = to_admin_alert(sample("langley", FleetCategory::PrinterOffline));
        assert_eq!(mapped.site_id, SiteId("langley".to_string()));
        assert_eq!(
            mapped.printer_id,
            Some(PrinterId::new("PRN-0001").unwrap())
        );
        assert_eq!(mapped.title, "Test alert");
        assert_eq!(mapped.description, "Extra detail");
    }

    #[test]
    fn to_admin_alert_empty_detail_becomes_empty_description() {
        let mut s = sample("langley", FleetCategory::PrinterOffline);
        s.detail = None;
        let mapped = to_admin_alert(s);
        assert_eq!(mapped.description, "");
    }

    #[test]
    fn map_category_folds_printer_variants() {
        assert_eq!(
            map_category(FleetCategory::PrinterOffline),
            AlertCategory::PrinterStatus
        );
        assert_eq!(
            map_category(FleetCategory::PrinterError),
            AlertCategory::PrinterStatus
        );
        assert_eq!(
            map_category(FleetCategory::HealthDegraded),
            AlertCategory::PrinterStatus
        );
    }

    #[test]
    fn map_category_folds_supply_variants() {
        assert_eq!(
            map_category(FleetCategory::TonerLow),
            AlertCategory::SupplyLow
        );
        assert_eq!(
            map_category(FleetCategory::PaperLow),
            AlertCategory::SupplyLow
        );
    }

    #[test]
    fn map_category_firmware_and_security() {
        assert_eq!(
            map_category(FleetCategory::FirmwareOutdated),
            AlertCategory::Firmware
        );
        assert_eq!(
            map_category(FleetCategory::StigViolation),
            AlertCategory::Security
        );
    }

    #[test]
    fn map_state_roundtrip() {
        assert_eq!(map_state(FleetState::Active), AlertState::Active);
        assert_eq!(
            map_state(FleetState::Acknowledged),
            AlertState::Acknowledged
        );
        assert_eq!(map_state(FleetState::Resolved), AlertState::Resolved);
    }

    #[test]
    fn map_severity_roundtrip() {
        assert_eq!(map_severity(FleetSeverity::Info), AlertSeverity::Info);
        assert_eq!(
            map_severity(FleetSeverity::Warning),
            AlertSeverity::Warning
        );
        assert_eq!(
            map_severity(FleetSeverity::Critical),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn nist_si4_alert_list_response_serializes() {
        // NIST 800-53 Rev 5: SI-4 — System Monitoring
        let response = AlertListResponse {
            alerts: vec![],
            total_count: 0,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"page\":1"));
    }
}
