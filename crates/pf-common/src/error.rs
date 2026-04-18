// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 `PrintForge` Contributors

//! Common error types shared across `PrintForge` crates.

use thiserror::Error;

/// Base error type for cross-crate operations.
#[derive(Debug, Error)]
pub enum CommonError {
    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),

    #[error("configuration error: {message}")]
    Config { message: String },

    #[error("serialization error")]
    Serialization(#[source] serde_json::Error),

    #[error("cryptographic operation failed: {message}")]
    Crypto { message: String },

    #[error("database error: {0}")]
    Database(String),
}

/// Input validation errors (NIST SI-10).
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("invalid EDIPI: {0}")]
    InvalidEdipi(String),

    #[error("invalid job ID: {0}")]
    InvalidJobId(String),

    #[error("invalid printer ID: {0}")]
    InvalidPrinterId(String),

    #[error("invalid cost center code: {0}")]
    InvalidCostCenter(String),

    #[error("field '{field}' is required")]
    RequiredField { field: String },

    #[error("field '{field}' exceeds maximum length {max}")]
    TooLong { field: String, max: usize },
}
