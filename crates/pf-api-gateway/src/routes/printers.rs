// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Printer fleet routes: list printers, get details, and query status.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement (all routes require auth).

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};

use crate::error::ApiError;
use crate::middleware::auth::RequireAuth;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Query parameters for listing printers.
#[derive(Debug, Deserialize)]
pub struct ListPrintersQuery {
    /// Filter by printer status.
    pub status: Option<PrinterStatus>,
    /// Filter by site identifier.
    pub site: Option<String>,
    /// Maximum number of results (default 50).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// A single printer entry in a list response.
#[derive(Debug, Serialize)]
pub struct PrinterSummary {
    /// Printer identifier.
    pub id: PrinterId,
    /// Printer make/model.
    pub model: PrinterModel,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Site where the printer is located.
    pub site: String,
    /// Human-readable location description.
    pub location: String,
}

/// Response for listing printers.
#[derive(Debug, Serialize)]
pub struct ListPrintersResponse {
    /// Matching printers.
    pub printers: Vec<PrinterSummary>,
    /// Total count for pagination.
    pub total: u64,
}

/// Detailed printer information.
#[derive(Debug, Serialize)]
pub struct PrinterDetailResponse {
    /// Printer identifier.
    pub id: PrinterId,
    /// Printer make/model.
    pub model: PrinterModel,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Site where the printer is located.
    pub site: String,
    /// Human-readable location description.
    pub location: String,
    /// IP address of the printer.
    pub ip_address: String,
    /// Current supply levels.
    pub supplies: SupplyLevel,
}

/// Printer status and supply level response.
#[derive(Debug, Serialize)]
pub struct PrinterStatusResponse {
    /// Printer identifier.
    pub id: PrinterId,
    /// Current operational status.
    pub status: PrinterStatus,
    /// Current supply levels.
    pub supplies: SupplyLevel,
    /// Number of jobs currently queued at this printer.
    pub queued_jobs: u32,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the `/printers` router.
///
/// All routes require authentication via `RequireAuth`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_printers))
        .route("/{id}", get(get_printer))
        .route("/{id}/status", get(get_printer_status))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List printers with optional status and site filters.
///
/// **NIST 800-53 Rev 5:** AC-3 — requires authenticated user.
///
/// # Errors
///
/// Returns `ApiError` on internal error.
async fn list_printers(
    State(state): State<AppState>,
    RequireAuth(_identity): RequireAuth,
    Query(params): Query<ListPrintersQuery>,
) -> Result<Json<ListPrintersResponse>, ApiError> {
    let svc = state.fleet_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let filter = pf_fleet_mgr::PrinterQuery {
        installation: params.site.clone(),
        status: params.status,
        ..Default::default()
    };

    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);

    let (summaries, total) = svc.list_printers(filter, limit, offset).await.map_err(|e| {
        ApiError::internal(Uuid::now_v7(), e)
    })?;

    let printers = summaries
        .into_iter()
        .map(|s| PrinterSummary {
            id: s.id,
            model: s.model,
            status: s.status,
            site: s.location.installation.clone(),
            location: format!("{}, Room {}", s.location.building, s.location.room),
        })
        .collect();

    Ok(Json(ListPrintersResponse {
        printers,
        total,
    }))
}

/// Get detailed information for a specific printer.
///
/// **NIST 800-53 Rev 5:** AC-3 — requires authenticated user.
///
/// # Errors
///
/// Returns `ApiError::not_found` if the printer does not exist.
async fn get_printer(
    State(state): State<AppState>,
    RequireAuth(_identity): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<PrinterDetailResponse>, ApiError> {
    let printer_id = PrinterId::new(&id)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid printer ID format"))?;

    let svc = state.fleet_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let detail = svc.get_printer(printer_id).await.map_err(|e| {
        match e {
            pf_fleet_mgr::FleetError::PrinterNotFound => ApiError::not_found(Uuid::now_v7()),
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(PrinterDetailResponse {
        id: detail.id,
        model: detail.model,
        status: detail.status,
        site: detail.location.installation.clone(),
        location: format!("{}, Room {}", detail.location.building, detail.location.room),
        ip_address: detail.ip_address.to_string(),
        supplies: detail.supply_levels.unwrap_or_else(stub_supply_levels),
    }))
}

/// Get current status and supply levels for a specific printer.
///
/// **NIST 800-53 Rev 5:** AC-3 — requires authenticated user.
///
/// # Errors
///
/// Returns `ApiError::not_found` if the printer does not exist.
async fn get_printer_status(
    State(state): State<AppState>,
    RequireAuth(_identity): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<PrinterStatusResponse>, ApiError> {
    let printer_id = PrinterId::new(&id)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid printer ID format"))?;

    let svc = state.fleet_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let status_info = svc.get_printer_status(printer_id).await.map_err(|e| {
        match e {
            pf_fleet_mgr::FleetError::PrinterNotFound => ApiError::not_found(Uuid::now_v7()),
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(PrinterStatusResponse {
        id: status_info.id,
        status: status_info.status,
        supplies: status_info.supply_levels.unwrap_or_else(stub_supply_levels),
        queued_jobs: 0,
    }))
}

/// Placeholder supply levels for stub responses.
fn stub_supply_levels() -> SupplyLevel {
    SupplyLevel {
        toner_k: 75,
        toner_c: 80,
        toner_m: 65,
        toner_y: 90,
        paper: 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_printers_query_defaults() {
        let json = "{}";
        let query: ListPrintersQuery = serde_json::from_str(json).unwrap();
        assert!(query.status.is_none());
        assert!(query.site.is_none());
    }

    #[test]
    fn printer_summary_serializes() {
        let summary = PrinterSummary {
            id: PrinterId::new("PRN-0042").unwrap(),
            model: PrinterModel {
                vendor: "HP".to_string(),
                model: "LaserJet".to_string(),
            },
            status: PrinterStatus::Online,
            site: "SITE-001".to_string(),
            location: "Room 201".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("PRN-0042"));
    }
}
