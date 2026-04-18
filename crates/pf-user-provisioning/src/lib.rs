// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! JIT provisioning, `SCIM` 2.0, and attribute synchronization for `PrintForge`.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! This crate manages the user lifecycle: Just-In-Time account creation from
//! OIDC/SAML claims, attribute synchronization on subsequent logins, role
//! mapping from `IdP` groups, cost center assignment, and account deprovisioning.
//! `PrintForge` never stores passwords — all authentication is delegated to
//! the `IdP`.

#![forbid(unsafe_code)]

pub mod attribute_sync;
pub mod claims;
pub mod config;
pub mod cost_center;
pub mod deprovisioning;
pub mod error;
pub mod jit;
pub mod pg_repo;
pub mod repository;
pub mod role_mapping;
pub mod scim;
pub mod service;
pub mod service_impl;
pub mod user;

// Re-exports for convenience.
pub use claims::NormalizedClaims;
pub use config::ProvisioningConfig;
pub use error::ProvisioningError;
pub use jit::{JitOutcome, provision_or_sync};
pub use repository::{InMemoryUserRepository, UserRepository};
pub use service::{UserFilter, UserService};
pub use service_impl::DefaultUserService;
pub use user::{ProvisionedUser, UserStatus};
