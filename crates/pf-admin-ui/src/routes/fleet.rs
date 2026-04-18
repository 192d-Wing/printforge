// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet overview route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All fleet queries are scoped by the
//! requester's [`DataScope`](crate::scope::DataScope) and translated into a
//! [`PrinterQuery::installations`] filter.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use pf_auth::middleware::RequireAuth;
use pf_common::fleet::SupplyLevel;
use pf_common::identity::SiteId;
use pf_fleet_mgr::{PrinterQuery, PrinterStatusCounts, PrinterSummary};

use crate::error::AdminUiError;
use crate::fleet_view::{FleetPrinterSummary, FleetStatusSummary, FleetViewResponse};
use crate::scope::{derive_scope, scope_to_installations};
use crate::state::AdminState;

/// Default page size when the client does not specify one.
const DEFAULT_PAGE_SIZE: u32 = 25;

/// Build the `/fleet` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/overview", get(fleet_overview))
        .route("/printers", get(list_printers))
}

/// `GET /fleet/overview` — Return aggregated fleet status summary, scoped
/// to the caller's authorized installations.
///
/// Backed by
/// [`FleetService::status_summary`](pf_fleet_mgr::FleetService::status_summary).
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` if the caller lacks an admin role.
/// - `AdminUiError::ServiceUnavailable` if the fleet service is not wired.
/// - `AdminUiError::Internal` on underlying fleet-service failure.
async fn fleet_overview(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<FleetStatusSummary>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let fleet = state
        .fleet
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "fleet" })?;

    let counts = fleet
        .status_summary(scope_to_installations(&scope))
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    Ok(Json(to_fleet_status_summary(&counts)))
}

/// Map the fleet-mgr [`PrinterStatusCounts`] onto the admin-ui wire type.
fn to_fleet_status_summary(c: &PrinterStatusCounts) -> FleetStatusSummary {
    FleetStatusSummary {
        online: c.online,
        offline: c.offline,
        error: c.error,
        maintenance: c.maintenance,
        printing: c.printing,
    }
}

/// `GET /fleet/printers` — Return a scoped printer list.
///
/// Backed by [`FleetService::list_printers`](pf_fleet_mgr::FleetService::list_printers)
/// with a site-scoped `installations` filter derived from the caller's roles.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` if the caller lacks an admin role.
/// - `AdminUiError::ServiceUnavailable` if the fleet service is not wired.
/// - `AdminUiError::Internal` on underlying fleet-service failure.
async fn list_printers(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<FleetViewResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let fleet = state
        .fleet
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "fleet" })?;

    let filter = PrinterQuery {
        installations: scope_to_installations(&scope),
        ..Default::default()
    };

    let (summaries, total_count) = fleet
        .list_printers(filter, DEFAULT_PAGE_SIZE, 0)
        .await
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    let printers = summaries
        .into_iter()
        .map(to_fleet_printer_summary)
        .collect();

    Ok(Json(FleetViewResponse {
        printers,
        total_count,
        page: 1,
        page_size: DEFAULT_PAGE_SIZE,
    }))
}

/// Map the fleet-mgr [`PrinterSummary`] onto the admin-ui wire type.
///
/// - `site_id` is derived from `PrinterLocation.installation`.
/// - `display_name` and `location` are synthesized from building + room; the
///   printer ID is used as a display fallback when location is empty.
/// - `health_score` is converted from the integer 0..=100 form to an `f64`
///   ratio in `[0.0, 1.0]`, defaulting to 0.0 when the record has no score.
/// - `supply_levels` falls back to all-zero when the record has no reading.
/// - `last_seen` falls back to `updated_at` when the printer has never
///   polled.
fn to_fleet_printer_summary(s: PrinterSummary) -> FleetPrinterSummary {
    let display_name = if s.location.building.is_empty() && s.location.room.is_empty() {
        s.id.as_str().to_string()
    } else {
        format!("Bldg {} Rm {}", s.location.building, s.location.room)
    };

    let location = format!(
        "Building {}, Room {}",
        s.location.building, s.location.room
    );

    let health_score = s.health_score.map_or(0.0, |h| f64::from(h) / 100.0);

    let supply_levels = s.supply_levels.unwrap_or(SupplyLevel {
        toner_k: 0,
        toner_c: 0,
        toner_m: 0,
        toner_y: 0,
        paper: 0,
    });

    let last_seen = s.last_polled_at.unwrap_or(s.updated_at);

    FleetPrinterSummary {
        printer_id: s.id,
        display_name,
        site_id: SiteId(s.location.installation.clone()),
        location,
        model: s.model,
        status: s.status,
        supply_levels,
        last_seen,
        health_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus};
    use pf_fleet_mgr::PrinterLocation;

    fn sample_fleet_summary(id: &str, installation: &str) -> PrinterSummary {
        PrinterSummary {
            id: PrinterId::new(id).unwrap(),
            model: PrinterModel {
                vendor: "HP".to_string(),
                model: "M609".to_string(),
            },
            status: PrinterStatus::Online,
            location: PrinterLocation {
                installation: installation.to_string(),
                building: "100".to_string(),
                floor: "2".to_string(),
                room: "201".to_string(),
            },
            supply_levels: Some(SupplyLevel {
                toner_k: 80,
                toner_c: 75,
                toner_m: 90,
                toner_y: 85,
                paper: 70,
            }),
            health_score: Some(92),
            updated_at: Utc::now(),
            last_polled_at: Some(Utc::now()),
        }
    }

    #[test]
    fn nist_ac3_to_fleet_printer_summary_maps_site_id_from_installation() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: the admin-ui `site_id` is sourced from the database
        // `location_installation` column, so site-scope filters applied at
        // the repository layer travel end-to-end to the client.
        let summary = sample_fleet_summary("PRN-0042", "langley");
        let mapped = to_fleet_printer_summary(summary);
        assert_eq!(mapped.site_id, SiteId("langley".to_string()));
    }

    #[test]
    fn to_fleet_printer_summary_synthesizes_display_name_and_location() {
        let summary = sample_fleet_summary("PRN-0042", "langley");
        let mapped = to_fleet_printer_summary(summary);
        assert_eq!(mapped.display_name, "Bldg 100 Rm 201");
        assert_eq!(mapped.location, "Building 100, Room 201");
    }

    #[test]
    fn to_fleet_printer_summary_falls_back_to_printer_id_when_location_empty() {
        let mut summary = sample_fleet_summary("PRN-0042", "langley");
        summary.location.building = String::new();
        summary.location.room = String::new();
        let mapped = to_fleet_printer_summary(summary);
        assert_eq!(mapped.display_name, "PRN-0042");
    }

    #[test]
    fn to_fleet_printer_summary_normalizes_health_score_to_ratio() {
        let summary = sample_fleet_summary("PRN-0042", "langley");
        let mapped = to_fleet_printer_summary(summary);
        assert!((mapped.health_score - 0.92).abs() < 1e-9);
    }

    #[test]
    fn to_fleet_printer_summary_defaults_health_score_when_unknown() {
        let mut summary = sample_fleet_summary("PRN-0042", "langley");
        summary.health_score = None;
        let mapped = to_fleet_printer_summary(summary);
        assert!((mapped.health_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn to_fleet_printer_summary_defaults_supplies_when_unreported() {
        let mut summary = sample_fleet_summary("PRN-0042", "langley");
        summary.supply_levels = None;
        let mapped = to_fleet_printer_summary(summary);
        assert_eq!(mapped.supply_levels.toner_k, 0);
        assert_eq!(mapped.supply_levels.paper, 0);
    }

    #[test]
    fn to_fleet_printer_summary_falls_back_last_seen_to_updated_at() {
        let mut summary = sample_fleet_summary("PRN-0042", "langley");
        summary.last_polled_at = None;
        let expected = summary.updated_at;
        let mapped = to_fleet_printer_summary(summary);
        assert_eq!(mapped.last_seen, expected);
    }

    #[test]
    fn fleet_overview_serializes() {
        let summary = FleetStatusSummary {
            online: 30,
            offline: 5,
            error: 2,
            maintenance: 3,
            printing: 10,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"online\":30"));
    }

    #[test]
    fn to_fleet_status_summary_copies_every_bucket() {
        let counts = PrinterStatusCounts {
            online: 30,
            offline: 5,
            error: 2,
            maintenance: 3,
            printing: 10,
        };
        let summary = to_fleet_status_summary(&counts);
        assert_eq!(summary.online, 30);
        assert_eq!(summary.offline, 5);
        assert_eq!(summary.error, 2);
        assert_eq!(summary.maintenance, 3);
        assert_eq!(summary.printing, 10);
    }

    #[test]
    fn fleet_view_response_includes_pagination() {
        let response = FleetViewResponse {
            printers: vec![],
            total_count: 0,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"page\":1"));
        assert!(json.contains("\"page_size\":25"));
    }
}
