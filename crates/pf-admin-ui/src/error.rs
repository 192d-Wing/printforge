// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-admin-ui` crate.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Errors returned by admin dashboard API operations.
///
/// Client-facing messages are intentionally generic to prevent information
/// leakage per NIST 800-53 Rev 5 SI-11.
#[derive(Debug, Error)]
pub enum AdminUiError {
    /// The requester does not have the required role for this endpoint.
    #[error("access denied")]
    AccessDenied,

    /// The requester's role does not grant visibility to the requested data scope.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    #[error("access denied")]
    ScopeViolation,

    /// A requested resource was not found.
    #[error("not found: {entity}")]
    NotFound {
        /// The type of entity that was not found.
        entity: String,
    },

    /// A backend service required to satisfy the request is not wired.
    ///
    /// Returned when the admin state's service handle for a given domain
    /// (fleet, jobs, accounting, audit, users) is `None`. Surfaced as HTTP
    /// 503 so clients and probes can distinguish this from authorization or
    /// input failures.
    #[error("service unavailable: {service}")]
    ServiceUnavailable {
        /// Short service name ("fleet", "jobs", "accounting", "audit", "users").
        service: &'static str,
    },

    /// Input validation failed.
    #[error("validation error: {0}")]
    Validation(#[from] pf_common::error::ValidationError),

    /// An internal error occurred that should not be exposed to the client.
    #[error("internal error")]
    Internal {
        /// Internal-only detail logged but not serialized to the client.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Serialization or deserialization failed.
    #[error("internal error")]
    Serialization(#[source] serde_json::Error),

    /// Report generation failed.
    #[error("report generation failed")]
    ReportGeneration {
        /// Internal reason (logged, not exposed).
        reason: String,
    },

    /// Policy update failed.
    #[error("policy update failed")]
    PolicyUpdate {
        /// Internal reason (logged, not exposed).
        reason: String,
    },
}

/// Convert `AdminUiError` into an Axum HTTP response.
///
/// Maps each variant to an appropriate HTTP status code with a sanitized
/// JSON body. Internal details are logged but never exposed to the client.
///
/// **NIST 800-53 Rev 5:** SI-11 — Error Handling
impl IntoResponse for AdminUiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::AccessDenied | Self::ScopeViolation => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
            Self::ServiceUnavailable { service } => {
                tracing::warn!(service = %service, "admin-ui service handle not configured");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service unavailable".to_string(),
                )
            }
            Self::Validation(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Internal { source } => {
                tracing::error!(error = %source, "internal admin UI error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            Self::Serialization(err) => {
                tracing::error!(error = %err, "serialization error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            Self::ReportGeneration { reason } => {
                tracing::error!(reason = %reason, "report generation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "report generation failed".to_string())
            }
            Self::PolicyUpdate { reason } => {
                tracing::error!(reason = %reason, "policy update failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "policy update failed".to_string())
            }
        };

        let body = serde_json::json!({
            "error": message,
        });

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_does_not_leak_details() {
        let err = AdminUiError::AccessDenied;
        assert_eq!(err.to_string(), "access denied");
    }

    #[test]
    fn scope_violation_does_not_leak_details() {
        let err = AdminUiError::ScopeViolation;
        assert_eq!(err.to_string(), "access denied");
    }

    #[test]
    fn internal_error_does_not_leak_details() {
        let inner = std::io::Error::other("db connection lost");
        let err = AdminUiError::Internal {
            source: Box::new(inner),
        };
        assert_eq!(err.to_string(), "internal error");
    }
}
