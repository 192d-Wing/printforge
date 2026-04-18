// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-driver-service` crate.

use thiserror::Error;

/// Errors that can occur within the `IPPS` driver service.
#[derive(Debug, Error)]
pub enum DriverServiceError {
    /// TLS configuration or handshake failure.
    #[error("TLS error: {message}")]
    Tls {
        /// Human-readable description of the TLS failure.
        message: String,
    },

    /// `IPP` message parsing failure.
    #[error("IPP parse error: {message}")]
    IppParse {
        /// Description of the malformed `IPP` content.
        message: String,
    },

    /// Unsupported or unknown `IPP` operation.
    #[error("unsupported IPP operation: 0x{operation_id:04x}")]
    UnsupportedOperation {
        /// The raw operation identifier from the `IPP` request.
        operation_id: u16,
    },

    /// The submitted document exceeds the configured maximum size.
    #[error("document too large: {size_bytes} bytes exceeds limit of {max_bytes} bytes")]
    DocumentTooLarge {
        /// Actual document size in bytes.
        size_bytes: u64,
        /// Configured maximum in bytes.
        max_bytes: u64,
    },

    /// The document format (MIME type) is not in the accepted list.
    #[error("unsupported document format: {mime_type}")]
    UnsupportedDocumentFormat {
        /// The MIME type submitted by the client.
        mime_type: String,
    },

    /// An `IPP` attribute failed validation.
    ///
    /// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
    #[error("invalid IPP attribute '{name}': {reason}")]
    InvalidAttribute {
        /// Attribute name.
        name: String,
        /// Why validation failed.
        reason: String,
    },

    /// Validation of common types (`Edipi`, `JobId`, etc.) failed.
    #[error("validation error: {0}")]
    Validation(#[from] pf_common::error::ValidationError),

    /// The connection was not established over TLS.
    ///
    /// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
    #[error("plaintext connection rejected — IPPS (TLS) required")]
    PlaintextRejected,

    /// Internal server error that should not leak details to clients.
    #[error("internal server error")]
    Internal {
        /// Internal details for logging only — never serialized to clients.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_does_not_leak_internal_details() {
        let err = DriverServiceError::Internal {
            source: Box::new(std::io::Error::other("secret db connection string")),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "internal server error");
        assert!(!msg.contains("secret"));
    }

    #[test]
    fn nist_sc8_plaintext_rejected_message() {
        let err = DriverServiceError::PlaintextRejected;
        let msg = format!("{err}");
        assert!(msg.contains("TLS"));
    }
}
