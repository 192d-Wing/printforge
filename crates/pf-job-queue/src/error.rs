// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-job-queue` crate.
//!
//! Error messages exposed to callers are sanitized to prevent information
//! leakage (NIST 800-53 Rev 5: SI-11).

use pf_common::error::ValidationError;
use pf_common::job::JobStatus;
use thiserror::Error;

/// Top-level error type for job queue operations.
#[derive(Debug, Error)]
pub enum JobQueueError {
    /// An invalid state transition was attempted on a job.
    #[error("invalid job state transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// The current state of the job.
        from: JobStatus,
        /// The attempted target state.
        to: JobStatus,
    },

    /// The requested job was not found.
    #[error("job not found")]
    NotFound,

    /// The releasing user does not own the job.
    #[error("authorization failed")]
    Unauthorized,

    /// Input validation failed.
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    /// A required IPP attribute was missing or unparseable.
    #[error("invalid IPP attribute: {attribute}")]
    InvalidIppAttribute {
        /// The name of the problematic IPP attribute.
        attribute: String,
        /// Internal detail (logged, not serialized to clients).
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The spool backend returned an error.
    #[error("spool operation failed")]
    Spool(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Policy evaluation denied the job.
    #[error("policy denied the job")]
    PolicyDenied {
        /// The violation returned by the policy engine.
        violation: pf_common::policy::PolicyViolation,
    },

    /// Database / repository persistence error.
    #[error("repository error")]
    Repository(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// NATS messaging error.
    #[error("sync error")]
    Sync(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Delivery to the target printer failed.
    #[error("delivery failed")]
    Delivery(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The job has already been purged and cannot be operated on.
    #[error("job has been purged")]
    AlreadyPurged,

    /// An internal error that should not be exposed to callers.
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}
