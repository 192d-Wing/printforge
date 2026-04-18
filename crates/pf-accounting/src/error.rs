// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-accounting` crate.

use thiserror::Error;

/// Errors that may occur during accounting operations.
#[derive(Debug, Error)]
pub enum AccountingError {
    /// The requested cost center was not found.
    #[error("cost center not found: {code}")]
    CostCenterNotFound {
        /// The cost center code that was not found.
        code: String,
    },

    /// The requested job cost record was not found.
    #[error("job cost not found for job {job_id}")]
    JobCostNotFound {
        /// The job ID that was not found.
        job_id: String,
    },

    /// The user's quota has been exceeded.
    #[error("quota exceeded: limit {limit}, used {used}, requested {requested}")]
    QuotaExceeded {
        /// Maximum pages allowed in the period.
        limit: u32,
        /// Pages already used in the period.
        used: u32,
        /// Pages requested by the current job.
        requested: u32,
    },

    /// A cost table entry is missing for the given configuration.
    #[error("cost table entry not found: {description}")]
    CostTableEntryNotFound {
        /// Description of the missing entry.
        description: String,
    },

    /// An invalid cost value was provided (e.g., negative cost).
    #[error("invalid cost value: {message}")]
    InvalidCostValue {
        /// Description of why the value is invalid.
        message: String,
    },

    /// The chargeback period is invalid or overlaps with an existing report.
    #[error("invalid chargeback period: {message}")]
    InvalidChargebackPeriod {
        /// Description of the period error.
        message: String,
    },

    /// An input validation error from `pf-common`.
    #[error("validation error: {0}")]
    Validation(#[from] pf_common::error::ValidationError),

    /// A database error occurred.
    #[error("database error")]
    Database(#[source] sqlx::Error),

    /// A serialization or deserialization error occurred.
    #[error("serialization error")]
    Serialization(#[source] serde_json::Error),
}
