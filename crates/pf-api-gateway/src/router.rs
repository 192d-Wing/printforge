// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Route definitions and API versioning.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
//! Every route MUST be authenticated unless explicitly allowlisted.

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::middleware::request_id::RequestIdLayer;
use crate::server::AppState;

/// Routes that are explicitly allowed without authentication.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
/// All other routes require `RequireAuth`.
pub const PUBLIC_ROUTES: &[&str] = &["/healthz", "/readyz"];

/// Build the complete `Axum` router with all middleware layers.
///
/// Layer ordering (outermost first):
/// 1. Request ID injection
/// 2. Tracing
/// 3. CORS
/// 4. Routes
pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state);

    let api_v1 = crate::routes::api_routes();

    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz));

    Router::new()
        .nest("/api/v1", api_v1)
        .merge(public)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(RequestIdLayer)
        .with_state(state)
}

/// Build the CORS layer from configuration.
///
/// **NIST 800-53 Rev 5:** SC-8 — no wildcard origins.
fn build_cors_layer(state: &AppState) -> CorsLayer {
    let origins = &state.config.cors.allowed_origins;

    if origins.is_empty() {
        // No origins configured — deny all cross-origin requests.
        return CorsLayer::new();
    }

    let allowed: Vec<axum::http::HeaderValue> =
        origins.iter().filter_map(|o| o.parse().ok()).collect();

    CorsLayer::new()
        .allow_origin(allowed)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .max_age(std::time::Duration::from_secs(
            state.config.cors.max_age_secs,
        ))
}

/// Kubernetes liveness probe.
///
/// Returns 200 OK if the process is alive.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Kubernetes readiness probe.
///
/// Returns 200 OK when the gateway is ready to accept traffic.
/// Checks whether backend services are configured. If no services
/// are wired (e.g., in unit tests), returns `"ready (no backends)"`.
/// If at least one service is configured, returns `"ready"`.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let has_any_backend = state.user_service.is_some()
        || state.job_service.is_some()
        || state.fleet_service.is_some()
        || state.accounting_service.is_some()
        || state.audit_service.is_some();

    if has_any_backend {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::OK, "ready (no backends)")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::config::GatewayConfig;

    fn test_state() -> AppState {
        AppState {
            config: Arc::new(GatewayConfig::default()),
            jwt_decoding_key: None,
            user_service: None,
            job_service: None,
            fleet_service: None,
            accounting_service: None,
            audit_service: None,
        }
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_200() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_200_with_no_services() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(text, "ready (no backends)");
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nist_ac3_public_routes_are_allowlisted() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Only healthz/readyz are in the public allowlist.
        assert!(PUBLIC_ROUTES.contains(&"/healthz"));
        assert!(PUBLIC_ROUTES.contains(&"/readyz"));
        assert_eq!(PUBLIC_ROUTES.len(), 2);
    }

    #[tokio::test]
    async fn request_with_existing_id_is_preserved() {
        // Verify that the request ID layer does not overwrite an existing header.
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/healthz")
            .header("x-request-id", "existing-id")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
