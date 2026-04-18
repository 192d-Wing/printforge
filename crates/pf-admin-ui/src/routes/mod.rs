// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Admin dashboard route handlers.
//!
//! Each submodule defines Axum route handlers for a specific admin domain.
//! All routes require authentication and enforce data scoping per the
//! requester's role.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement

pub mod alerts;
pub mod dashboard;
pub mod fleet;
pub mod jobs;
pub mod reports;
pub mod users;

use axum::Router;

use crate::state::AdminState;

/// Build the combined admin dashboard API router.
///
/// Mounts each route module under its path prefix. All routes extract the
/// caller's [`Identity`](pf_common::identity::Identity) via
/// [`pf_auth::middleware::RequireAuth`] and enforce data scope via
/// [`derive_scope`](crate::scope::derive_scope).
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
pub fn admin_routes() -> Router<AdminState> {
    Router::new()
        .nest("/dashboard", dashboard::router())
        .nest("/reports", reports::router())
        .nest("/alerts", alerts::router())
        .nest("/fleet", fleet::router())
        .nest("/jobs", jobs::router())
        .nest("/users", users::router())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_routes_builds_without_panic() {
        let _router: Router<AdminState> = admin_routes();
    }
}
