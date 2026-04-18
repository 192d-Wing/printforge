// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Health-check endpoints for Kubernetes liveness and readiness probes.
//!
//! These endpoints are **public** — no authentication is required.
//! They are explicitly allowlisted in `router::PUBLIC_ROUTES`.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde::Serialize;

use crate::server::AppState;

/// Health-check response body.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Current status: `"ok"` or `"degraded"`.
    pub status: String,
}

/// Build the health-check router.
///
/// Registers `/healthz` and `/readyz` as `GET` endpoints.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

/// Kubernetes liveness probe.
///
/// Returns 200 OK if the process is alive.
async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Kubernetes readiness probe.
///
/// Returns 200 OK when the gateway is ready to accept traffic.
/// Checks whether backend services are configured. If no services
/// are wired (e.g., in unit tests), returns `"ready (no backends)"`.
/// If at least one service is configured, returns `"ready"`.
async fn readyz(State(state): State<AppState>) -> Json<HealthResponse> {
    let has_any_backend = state.user_service.is_some()
        || state.job_service.is_some()
        || state.fleet_service.is_some()
        || state.accounting_service.is_some()
        || state.audit_service.is_some();

    let status = if has_any_backend {
        "ready".to_string()
    } else {
        "ready (no backends)".to_string()
    };

    Json(HealthResponse { status })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_serializes() {
        let resp = HealthResponse {
            status: "ok".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("ok"));
    }
}
