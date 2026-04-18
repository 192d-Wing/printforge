// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Self-service enrollment portal for `PrintForge`.
//!
//! Provides zero-touch user onboarding: new users navigate to the enrollment
//! URL, acknowledge the `DoD` consent banner (AC-8), authenticate via their
//! organization's identity provider (`Entra ID` on `NIPR`, DISA E-ICAM on
//! `SIPR`), and are automatically provisioned with a `PrintForge` account
//! via JIT provisioning. Also serves as a driver download hub and user
//! profile management page.
//!
//! **NIST 800-53 Rev 5 Controls:** AC-2 (Account Management), AC-8 (System Use Notification)

#![forbid(unsafe_code)]

pub mod banner;
pub mod callback;
pub mod config;
pub mod driver_hub;
pub mod enrollment;
pub mod error;
pub mod idp_redirect;
pub mod profile;
pub mod routes;

// Re-exports for convenience.
pub use banner::{BannerAcknowledgment, BannerPresentation};
pub use callback::{CallbackResult, OidcCallbackParams, SamlCallbackParams};
pub use config::{Enclave, EnrollPortalConfig};
pub use driver_hub::{Architecture, DriverDownloadLink, DriverPackage, OperatingSystem};
pub use enrollment::{EnrollmentOutcome, EnrollmentPhase, EnrollmentSession};
pub use error::EnrollmentError;
pub use idp_redirect::RedirectResult;
pub use profile::{ColorMode, DuplexMode, UserPreferences, UserProfile};
pub use routes::{portal_routes, EnrollState};
