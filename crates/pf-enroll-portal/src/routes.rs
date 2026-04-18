// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Axum route handlers for the self-service enrollment portal.
//!
//! This module exposes three public endpoints that do NOT require an
//! authenticated `Identity`:
//!
//! - `GET /banner` — returns the `DoD` consent banner (AC-8).
//! - `GET /drivers` — returns the driver catalog with download links.
//! - `GET /idp/redirect` — returns the `IdP` authorization URL.
//!
//! The `IdP` callback endpoints (`POST /callback/oidc`, `POST /callback/saml`)
//! and the authenticated profile endpoints (`GET /profile`,
//! `PATCH /profile`) are intentionally NOT mounted here yet — they require
//! `UserService` JIT provisioning and JWT signing wired into the portal
//! state, which is scheduled for a follow-up slice. The existing logic in
//! [`crate::callback`] and [`crate::profile`] is complete and unit-tested;
//! only the HTTP wrappers are missing.
//!
//! **NIST 800-53 Rev 5:** AC-8 — System Use Notification, IA-8 — IA for
//! Non-Organizational Users

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::banner::{build_banner_presentation, BannerPresentation};
use crate::config::EnrollPortalConfig;
use crate::driver_hub::{
    build_download_links, DriverDownloadLink, DriverPackage, OperatingSystem,
};
use crate::error::EnrollmentError;
use crate::idp_redirect::{initiate_redirect, RedirectResult};

/// Shared state for the enrollment portal router.
#[derive(Clone)]
pub struct EnrollState {
    /// Loaded portal configuration (enclave, `IdP` config, banner text,
    /// driver hub config).
    pub config: Arc<EnrollPortalConfig>,
    /// Catalog of available driver packages. Intentionally held as a
    /// snapshot rather than scanned from disk per-request.
    pub packages: Arc<Vec<DriverPackage>>,
}

impl std::fmt::Debug for EnrollState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollState")
            .field("enclave", &self.config.enclave)
            .field("package_count", &self.packages.len())
            .finish()
    }
}

/// Build the enrollment portal router.
///
/// Mount under a public-route prefix (e.g. `/enroll`); none of these
/// handlers require an authenticated `Identity`.
pub fn portal_routes() -> Router<EnrollState> {
    Router::new()
        .route("/banner", get(get_banner))
        .route("/drivers", get(get_drivers))
        .route("/idp/redirect", get(get_idp_redirect))
}

/// `GET /banner` — Return the `DoD` consent banner for display before the
/// `IdP` redirect.
///
/// Every call generates a fresh nonce; the client MUST round-trip that
/// nonce through acknowledgment before the redirect endpoint will succeed.
///
/// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if nonce generation fails.
async fn get_banner(
    State(state): State<EnrollState>,
) -> Result<Json<BannerPresentation>, EnrollmentError> {
    let presentation = build_banner_presentation(&state.config.banner)?;
    Ok(Json(presentation))
}

/// Query parameters for `GET /drivers`.
#[derive(Debug, Deserialize)]
pub struct DriversQuery {
    /// `User-Agent` header value (populated by the caller) for OS
    /// auto-detection. Absent / unrecognized ⇒ no recommendation.
    pub user_agent: Option<String>,
}

/// Response body for `GET /drivers`.
#[derive(Debug, Serialize)]
pub struct DriversResponse {
    /// The detected operating system, if any.
    pub detected_os: Option<OperatingSystem>,
    /// All available packages with their signed download links. Entries
    /// matching the detected OS have `recommended = true`.
    pub links: Vec<DriverDownloadLink>,
}

/// `GET /drivers?user_agent=...` — Return the driver catalog with per-OS
/// download links. Unauthenticated (the catalog is public by design; the
/// platform is open-source and drivers are signed).
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if download URL construction fails.
async fn get_drivers(
    State(state): State<EnrollState>,
    Query(params): Query<DriversQuery>,
) -> Result<Json<DriversResponse>, EnrollmentError> {
    let detected_os = params
        .user_agent
        .as_deref()
        .and_then(OperatingSystem::from_user_agent);
    let links = build_download_links(&state.config.driver_hub, &state.packages, detected_os)?;
    Ok(Json(DriversResponse {
        detected_os,
        links,
    }))
}

/// Response body for `GET /idp/redirect`. Returned as `JSON` so the SPA can
/// decide between a full navigation and an iframe; the handler intentionally
/// does not issue a 302 itself.
#[derive(Debug, Serialize)]
pub struct IdpRedirectResponse {
    /// The URL the client should navigate to (`OIDC` authorize or `SAML` SSO).
    pub redirect_url: Url,
    /// Protocol the `IdP` expects. Drives the callback endpoint the client
    /// should eventually POST to.
    pub protocol: &'static str,
}

/// `GET /idp/redirect` — Construct the enclave-appropriate authorization
/// URL. `NIPR` returns an `OIDC` authorize URL (`PKCE`); `SIPR` returns a
/// `SAML` `AuthnRequest` URL.
///
/// Flow state required for callback validation (`PKCE` verifier,
/// `AuthnRequest` id) is NOT persisted here yet — the SPA must keep it
/// client-side, or a server-side session store lands in a follow-up slice.
///
/// **NIST 800-53 Rev 5:** IA-8 — IA for Non-Organizational Users
///
/// # Errors
///
/// Returns `EnrollmentError::EnclaveConfigInvalid` when the enclave's
/// `IdP` configuration is missing.
async fn get_idp_redirect(
    State(state): State<EnrollState>,
) -> Result<Json<IdpRedirectResponse>, EnrollmentError> {
    let result = initiate_redirect(&state.config)?;
    let (redirect_url, protocol) = match result {
        RedirectResult::Oidc { redirect_url, .. } => (redirect_url, "oidc"),
        RedirectResult::Saml { redirect_url, .. } => (redirect_url, "saml"),
    };
    Ok(Json(IdpRedirectResponse {
        redirect_url,
        protocol,
    }))
}

// ── IntoResponse for EnrollmentError ─────────────────────────────────

impl axum::response::IntoResponse for EnrollmentError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, body) = match &self {
            EnrollmentError::BannerNotAcknowledged => (
                StatusCode::BAD_REQUEST,
                "banner acknowledgment required",
            ),
            EnrollmentError::DriverNotFound { .. } => (StatusCode::NOT_FOUND, "driver not found"),
            EnrollmentError::EnclaveConfigInvalid(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "enrollment not configured for this enclave",
            ),
            EnrollmentError::AuthenticationFailed(_) => {
                (StatusCode::UNAUTHORIZED, "authentication failed")
            }
            EnrollmentError::Internal(_) => {
                tracing::error!(error = %self, "internal enrollment error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            _ => {
                tracing::warn!(error = %self, "unhandled enrollment error");
                (StatusCode::BAD_REQUEST, "enrollment error")
            }
        };
        (status, body.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_routes_builds_without_panic() {
        let _router: Router<EnrollState> = portal_routes();
    }
}
