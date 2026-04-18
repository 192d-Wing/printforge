// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-policy-engine` crate.
//!
//! **NIST 800-53 Rev 5:** CM-7 — Least Functionality
//! Error messages are sanitized before exposure to clients; internal details
//! are logged but never returned in API responses.

use thiserror::Error;

/// Errors that may occur during policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The `OPA` sidecar is unreachable or returned a non-200 response.
    /// Default-deny: the job is held.
    #[error("policy engine unavailable")]
    OpaUnavailable(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The `OPA` response could not be deserialized into a decision.
    #[error("policy engine returned invalid response")]
    InvalidResponse(String),

    /// The policy input failed validation before being sent to `OPA`.
    #[error("policy input validation failed: {0}")]
    InputValidation(String),

    /// A database error occurred while reading or updating quota counters.
    #[error("quota storage error")]
    QuotaStorage(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The embedded `Rego` evaluator encountered an error.
    #[error("embedded policy evaluation failed")]
    EmbeddedEvaluation(String),

    /// A required configuration value is missing or invalid.
    #[error("policy configuration error: {0}")]
    Config(String),
}
