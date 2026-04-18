// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `OPA`/`Rego` print policy evaluation for `PrintForge`.
//!
//! This crate evaluates print jobs and user actions against organizationally
//! defined policies using Open Policy Agent (`OPA`) with the `Rego` policy
//! language. It enforces quota limits, color restrictions, duplex defaults,
//! classification-based routing, and page limits.
//!
//! **NIST 800-53 Rev 5:** AC-3 (Access Enforcement), AC-6 (Least Privilege),
//! CM-7 (Least Functionality — default-deny)
//!
//! # Default-Deny
//!
//! If `OPA` is unreachable or returns an error, the job is **held** (not
//! printed). This is the fail-closed pattern required by organizational
//! security policy.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod decision;
pub mod defaults;
pub mod embedded;
pub mod error;
pub mod input;
pub mod quota;
pub mod repository;

// Re-export primary API surface
pub use config::PolicyConfig;
pub use decision::{evaluate_job, evaluate_job_default_deny};
pub use defaults::DefaultOverrides;
pub use error::PolicyError;
pub use input::{PolicyInput, PrinterCapabilities};
pub use repository::PolicyRepository;
