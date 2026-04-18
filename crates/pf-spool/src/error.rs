// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-spool` crate.

use thiserror::Error;

/// Errors that can occur during spool operations.
#[derive(Debug, Error)]
pub enum SpoolError {
    /// Encryption or decryption failed.
    #[error("encryption operation failed")]
    Encryption(String),

    /// DEK generation failed.
    #[error("key generation failed")]
    KeyGeneration(String),

    /// KEK wrapping or unwrapping failed.
    #[error("key wrapping operation failed")]
    KeyWrap(String),

    /// KEK not found in the key store.
    #[error("KEK not found: {0}")]
    KekNotFound(String),

    /// S3 object storage operation failed.
    #[error("storage operation failed")]
    Storage(String),

    /// The requested spool object was not found.
    #[error("spool object not found: {0}")]
    NotFound(String),

    /// Spool data integrity check failed (AEAD tag mismatch).
    #[error("data integrity check failed")]
    IntegrityFailure,

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Serialization / deserialization error.
    #[error("serialization error")]
    Serialization(#[from] serde_json::Error),

    /// Retention policy violation.
    #[error("retention policy violation: {0}")]
    RetentionViolation(String),

    /// An error from `pf-common`.
    #[error(transparent)]
    Common(#[from] pf_common::error::CommonError),
}
