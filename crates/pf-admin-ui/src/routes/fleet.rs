// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet overview route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-3 — All fleet queries are scoped by the
//! requester's [`DataScope`](crate::scope::DataScope).

use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;

use pf_auth::middleware::RequireAuth;
use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};
use pf_common::identity::SiteId;

use crate::error::AdminUiError;
use crate::fleet_view::{FleetPrinterSummary, FleetStatusSummary, FleetViewResponse};
use crate::scope::{derive_scope, DataScope};
use crate::state::AdminState;

/// Build the `/fleet` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/overview", get(fleet_overview))
        .route("/printers", get(list_printers))
}

/// Build stub printer data scoped to the requester's authorized sites.
fn stub_printers(scope: &DataScope) -> Vec<FleetPrinterSummary> {
    let all_printers = vec![
        FleetPrinterSummary {
            printer_id: PrinterId::new("PRN-0042").expect("valid stub printer ID"),
            display_name: "Bldg 100 Rm 201".to_string(),
            site_id: SiteId("langley".to_string()),
            location: "Building 100, Room 201".to_string(),
            model: PrinterModel {
                vendor: "HP".to_string(),
                model: "LaserJet Enterprise M609".to_string(),
            },
            status: PrinterStatus::Online,
            supply_levels: SupplyLevel {
                toner_k: 75,
                toner_c: 80,
                toner_m: 65,
                toner_y: 90,
                paper: 50,
            },
            last_seen: Utc::now(),
            health_score: 0.92,
        },
        FleetPrinterSummary {
            printer_id: PrinterId::new("PRN-0099").expect("valid stub printer ID"),
            display_name: "Bldg 300 Rm 102".to_string(),
            site_id: SiteId("ramstein".to_string()),
            location: "Building 300, Room 102".to_string(),
            model: PrinterModel {
                vendor: "Xerox".to_string(),
                model: "VersaLink C405".to_string(),
            },
            status: PrinterStatus::Online,
            supply_levels: SupplyLevel {
                toner_k: 5,
                toner_c: 60,
                toner_m: 55,
                toner_y: 70,
                paper: 80,
            },
            last_seen: Utc::now(),
            health_score: 0.45,
        },
    ];

    match scope {
        DataScope::Global => all_printers,
        DataScope::Sites(sites) => all_printers
            .into_iter()
            .filter(|p| sites.contains(&p.site_id))
            .collect(),
    }
}

/// `GET /fleet/overview` — Return aggregated fleet status summary.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester lacks admin access.
async fn fleet_overview(
    RequireAuth(identity): RequireAuth,
) -> Result<Json<FleetStatusSummary>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let printers = stub_printers(&scope);

    let mut summary = FleetStatusSummary {
        online: 0,
        offline: 0,
        error: 0,
        maintenance: 0,
        printing: 0,
    };

    for p in &printers {
        match p.status {
            PrinterStatus::Online => summary.online += 1,
            PrinterStatus::Offline => summary.offline += 1,
            PrinterStatus::Error => summary.error += 1,
            PrinterStatus::Maintenance => summary.maintenance += 1,
            PrinterStatus::Printing => summary.printing += 1,
        }
    }

    Ok(Json(summary))
}

/// `GET /fleet/printers` — Return a scoped printer list.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester lacks admin access.
async fn list_printers(
    RequireAuth(identity): RequireAuth,
) -> Result<Json<FleetViewResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let printers = stub_printers(&scope);
    let total_count = printers.len() as u64;

    Ok(Json(FleetViewResponse {
        printers,
        total_count,
        page: 1,
        page_size: 25,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn nist_ac3_site_admin_sees_only_own_site_printers() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Site admin for langley cannot see ramstein printers.
        let scope = DataScope::Sites(vec![SiteId("langley".to_string())]);
        let printers = stub_printers(&scope);
        assert!(printers
            .iter()
            .all(|p| p.site_id == SiteId("langley".to_string())));
        assert!(!printers.is_empty());
    }

    #[test]
    fn nist_ac3_global_scope_sees_all_printers() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Fleet admin sees printers from all sites.
        let scope = DataScope::Global;
        let printers = stub_printers(&scope);
        let sites: Vec<&SiteId> = printers.iter().map(|p| &p.site_id).collect();
        assert!(sites.contains(&&SiteId("langley".to_string())));
        assert!(sites.contains(&&SiteId("ramstein".to_string())));
    }

    #[test]
    fn fleet_view_response_includes_pagination() {
        let printers = stub_printers(&DataScope::Global);
        let response = FleetViewResponse {
            total_count: printers.len() as u64,
            printers,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"page\":1"));
        assert!(json.contains("\"page_size\":25"));
    }
}
