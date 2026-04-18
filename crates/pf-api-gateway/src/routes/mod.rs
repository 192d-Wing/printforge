// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! API route modules for the `PrintForge` gateway.
//!
//! Each submodule defines route handlers for a specific domain and exposes
//! a `router()` function that returns a configured `axum::Router`.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
//! All routes except health probes require authentication.

pub mod accounting;
pub mod audit;
pub mod health;
pub mod jobs;
pub mod printers;
pub mod users;

use axum::Router;

use crate::server::AppState;

/// Build the combined API router containing all versioned route groups.
///
/// Mounts each route module under its path prefix. Health endpoints are
/// mounted at the root (outside `/api/v1`) so Kubernetes probes work
/// without authentication.
///
/// # Returns
///
/// An `axum::Router` with all route groups nested under `/api/v1`.
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .nest("/jobs", jobs::router())
        .nest("/printers", printers::router())
        .nest("/users", users::router())
        .nest("/audit", audit::router())
        .nest("/accounting", accounting::router())
}

/// Build the public (unauthenticated) health probe routes.
///
/// These are mounted at the root, outside `/api/v1`.
pub fn health_routes() -> Router<AppState> {
    health::router()
}
