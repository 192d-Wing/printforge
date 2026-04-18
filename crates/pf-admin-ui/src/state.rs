// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Axum state for the admin dashboard router.
//!
//! [`AdminState`] carries the JWT verification configuration needed by
//! [`pf_auth::middleware::RequireAuth`]. In later milestones it will also
//! carry handles to the backend services that supply real data (fleet, jobs,
//! accounting, audit, users).
//!
//! **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication,
//! AC-3 — Access Enforcement

use std::sync::Arc;

use jsonwebtoken::DecodingKey;
use pf_auth::middleware::HasJwtConfig;

/// Shared state for the admin dashboard router.
///
/// Cheap to clone: string fields are held behind `Arc<str>`, and the decoding
/// key behind `Arc<DecodingKey>`. Axum clones the state on every request.
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
            .finish()
    }
}

#[cfg(test)]
impl AdminState {
    /// Build an `AdminState` for tests — no decoding key, so every request
    /// authenticating against it will be rejected.
    #[must_use]
    pub fn test_unconfigured() -> Self {
        Self {
            jwt_decoding_key: None,
            jwt_issuer: Arc::from("printforge"),
            jwt_audience: Arc::from("printforge-api"),
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
