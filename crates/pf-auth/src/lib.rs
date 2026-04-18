// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Identity and authentication service for `PrintForge`.
//!
//! This crate implements all authentication flows:
//! - OIDC Authorization Code Flow with PKCE (`Entra ID` on NIPR)
//! - SAML 2.0 SP-initiated SSO (DISA E-ICAM on SIPR)
//! - CAC/PIV X.509 certificate validation (both enclaves)
//! - OCSP/CRL revocation checking
//! - JWT issuance for authenticated sessions (Ed25519 via `ring`)
//! - CAC PIN validation state machine
//! - Axum middleware extractors for authentication and authorization
//!
//! **NIST 800-53 Rev 5 Controls:** IA-2, IA-5, IA-5(2), IA-8, AC-3, AC-7, SC-12, SC-17

#![forbid(unsafe_code)]

pub mod certificate;
pub mod config;
pub mod crl;
pub mod error;
pub mod jwt;
pub mod middleware;
pub mod ocsp;
pub mod oidc;
pub mod pin;
pub mod saml;
pub mod trust_store;

// Re-exports for convenience.
pub use certificate::{ParsedCertificate, extract_edipi_from_cn, validate_chain};
pub use config::AuthConfig;
pub use error::AuthError;
pub use jwt::{PrintForgeClaims, TokenScope};
pub use middleware::{AuthRejection, HasJwtConfig, RequireAuth, RequireRole};
pub use ocsp::{OcspCache, OcspStatus};
pub use pin::{PinState, PinTracker};
pub use trust_store::TrustStore;
