// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error type for the pf-reports crate.

use thiserror::Error;

/// Errors produced by report persistence and service operations.
#[derive(Debug, Error)]
pub enum ReportError {
    /// No report with the given ID exists.
    #[error("report not found")]
    NotFound,

    /// The requested date range is invalid.
    #[error("invalid reporting period: {reason}")]
    InvalidPeriod {
        /// Why the period was rejected.
        reason: String,
    },

    /// Persistence layer failure.
    #[error("repository operation failed")]
    Repository(#[source] sqlx::Error),
}
