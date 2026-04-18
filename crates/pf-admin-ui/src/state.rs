// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Axum state for the admin dashboard router.
//!
//! [`AdminState`] carries the JWT verification configuration needed by
//! [`pf_auth::middleware::RequireAuth`] and handles to the backend services
//! that supply real data for the admin dashboard.
//!
//! **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication,
//! AC-3 — Access Enforcement

use std::sync::Arc;

use jsonwebtoken::DecodingKey;
use pf_auth::middleware::HasJwtConfig;

/// Shared state for the admin dashboard router.
///
/// Cheap to clone: string fields are held behind `Arc<str>`, the decoding key
/// behind `Arc<DecodingKey>`, and each service handle behind `Arc<dyn ...>`.
/// Axum clones the state on every request.
///
/// Service handles are `Option`al so the gateway can stand up without every
/// backend wired (unit tests, early deployments). A handler that needs a
/// service returns [`AdminUiError::ServiceUnavailable`](crate::error::AdminUiError)
/// when its handle is `None`.
#[derive(Clone)]
pub struct AdminState {
    /// Ed25519 public key for JWT signature verification.
    /// `None` disables authentication — every request will be rejected.
    ///
    /// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
    pub jwt_decoding_key: Option<Arc<DecodingKey>>,

    /// Expected JWT `iss` claim.
    pub jwt_issuer: Arc<str>,

    /// Expected JWT `aud` claim.
    pub jwt_audience: Arc<str>,

    /// Fleet management service — source of truth for printers and status.
    pub fleet: Option<Arc<dyn pf_fleet_mgr::FleetService>>,

    /// Job queue service — held/active/completed job listings.
    pub jobs: Option<Arc<dyn pf_job_queue::JobService>>,

    /// Accounting service — quota status, monthly usage, chargeback reports.
    pub accounting: Option<Arc<dyn pf_accounting::AccountingService>>,

    /// Audit service — NIST evidence export, compliance reports.
    pub audit: Option<Arc<dyn pf_audit::AuditService>>,

    /// User provisioning service — user listings, role assignments.
    pub users: Option<Arc<dyn pf_user_provisioning::UserService>>,

    /// Fleet alert service — list + acknowledge.
    pub alerts: Option<Arc<dyn pf_fleet_mgr::AlertService>>,
}

impl HasJwtConfig for AdminState {
    fn jwt_decoding_key(&self) -> Option<&DecodingKey> {
        self.jwt_decoding_key.as_deref()
    }

    fn jwt_issuer(&self) -> &str {
        &self.jwt_issuer
    }

    fn jwt_audience(&self) -> &str {
        &self.jwt_audience
    }
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("jwt_decoding_key", &self.jwt_decoding_key.is_some())
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("fleet", &self.fleet.is_some())
            .field("jobs", &self.jobs.is_some())
            .field("accounting", &self.accounting.is_some())
            .field("audit", &self.audit.is_some())
            .field("users", &self.users.is_some())
            .field("alerts", &self.alerts.is_some())
            .finish()
    }
}

#[cfg(test)]
impl AdminState {
    /// Build an `AdminState` for tests — no decoding key, no service handles.
    /// Every auth-requiring request will be rejected and every service-using
    /// handler will return `ServiceUnavailable`.
    #[must_use]
    pub fn test_unconfigured() -> Self {
        Self {
            jwt_decoding_key: None,
            jwt_issuer: Arc::from("printforge"),
            jwt_audience: Arc::from("printforge-api"),
            fleet: None,
            jobs: None,
            accounting: None,
            audit: None,
            users: None,
            alerts: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_state_clones_cheaply() {
        let state = AdminState::test_unconfigured();
        let cloned = state.clone();
        assert_eq!(cloned.jwt_issuer(), "printforge");
        assert_eq!(cloned.jwt_audience(), "printforge-api");
        assert!(cloned.jwt_decoding_key().is_none());
    }
}
