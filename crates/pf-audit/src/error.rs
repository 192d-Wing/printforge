// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-audit` crate.

use thiserror::Error;

/// Errors produced by audit operations.
#[derive(Debug, Error)]
pub enum AuditError {
    /// An audit event failed schema validation.
    #[error("audit event validation failed: {message}")]
    Validation {
        /// Human-readable description of the validation failure.
        message: String,
    },

    /// The audit persistence layer encountered a database error.
    #[error("audit persistence failed")]
    Persistence(#[source] sqlx::Error),

    /// Serialization of an audit record failed.
    #[error("audit serialization failed")]
    Serialization(#[source] serde_json::Error),

    /// The SIEM export transport failed.
    #[error("SIEM export failed: {message}")]
    SiemExport {
        /// Description of the transport failure (no internal details).
        message: String,
    },

    /// The `eMASS` artifact generation failed.
    #[error("eMASS artifact generation failed: {message}")]
    EmassGeneration {
        /// Description of the generation failure.
        message: String,
    },

    /// An audit query was malformed or out of range.
    #[error("invalid audit query: {message}")]
    InvalidQuery {
        /// Description of the query problem.
        message: String,
    },

    /// The retention policy encountered an error during archival.
    #[error("retention archival failed: {message}")]
    Retention {
        /// Description of the retention failure.
        message: String,
    },

    /// Configuration is invalid or missing.
    #[error("audit configuration error: {message}")]
    Config {
        /// Description of the configuration problem.
        message: String,
    },
}
