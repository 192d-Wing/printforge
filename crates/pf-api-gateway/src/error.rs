// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! API error types with sanitized bodies for external responses.
//!
//! **NIST 800-53 Rev 5:** SI-11 — Error Handling
//! Error responses return a request ID and a generic message. The full
//! error chain is logged server-side for correlation.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use uuid::Uuid;

/// Structured error response body returned to API clients.
///
/// Contains only a request ID for correlation and a sanitized message.
/// Internal details are never exposed.
///
/// **NIST 800-53 Rev 5:** SI-11 — Error Handling
#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    /// Unique identifier for this request, used to correlate with server logs.
    pub request_id: String,
    /// HTTP status code.
    pub status: u16,
    /// Human-readable error message. Never contains internal details.
    pub message: String,
}

/// API-level error type that maps to HTTP status codes.
///
/// Internal error details are captured in the `internal` field for
/// server-side logging but are never serialized to the client.
///
/// **NIST 800-53 Rev 5:** SI-11 — Error Handling
#[derive(Debug)]
pub struct ApiError {
    /// The HTTP status code to return.
    pub status: StatusCode,
    /// Sanitized message visible to the client.
    pub message: String,
    /// Request ID for log correlation.
    pub request_id: Uuid,
    /// Internal error details, logged server-side only.
    pub internal: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ApiError {
    /// Create a 400 Bad Request error.
    #[must_use]
    pub fn bad_request(request_id: Uuid, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            request_id,
            internal: None,
        }
    }

    /// Create a 401 Unauthorized error.
    #[must_use]
    pub fn unauthorized(request_id: Uuid) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "authentication required".to_string(),
            request_id,
            internal: None,
        }
    }

    /// Create a 403 Forbidden error.
    #[must_use]
    pub fn forbidden(request_id: Uuid) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "access denied".to_string(),
            request_id,
            internal: None,
        }
    }

    /// Create a 404 Not Found error.
    #[must_use]
    pub fn not_found(request_id: Uuid) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "resource not found".to_string(),
            request_id,
            internal: None,
        }
    }

    /// Create a 429 Too Many Requests error with a `Retry-After` hint.
    #[must_use]
    pub fn too_many_requests(request_id: Uuid, retry_after_secs: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: format!("rate limit exceeded, retry after {retry_after_secs}s"),
            request_id,
            internal: None,
        }
    }

    /// Create a 503 Service Unavailable error.
    ///
    /// Returned when a backend service is not configured or is temporarily
    /// unavailable.
    #[must_use]
    pub fn service_unavailable(request_id: Uuid) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "service unavailable".to_string(),
            request_id,
            internal: None,
        }
    }

    /// Create a 500 Internal Server Error, logging the internal cause.
    #[must_use]
    pub fn internal(
        request_id: Uuid,
        cause: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
            request_id,
            internal: Some(cause.into()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log internal details server-side with the request ID for correlation.
        if let Some(ref cause) = self.internal {
            tracing::error!(
                request_id = %self.request_id,
                error = %cause,
                "internal error"
            );
        }

        let body = ApiErrorBody {
            request_id: self.request_id.to_string(),
            status: self.status.as_u16(),
            message: self.message,
        };

        (self.status, axum::Json(body)).into_response()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.request_id, self.status, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_si11_error_body_omits_internal_details() {
        // NIST 800-53 Rev 5: SI-11 — Error Handling
        // Evidence: internal error details are not serialized.
        let err = ApiError::internal(
            Uuid::nil(),
            std::io::Error::other("secret DB connection string"),
        );
        let body = ApiErrorBody {
            request_id: err.request_id.to_string(),
            status: err.status.as_u16(),
            message: err.message.clone(),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("secret DB connection string"));
        assert!(json.contains("internal server error"));
    }

    #[test]
    fn nist_si11_bad_request_returns_400() {
        let err = ApiError::bad_request(Uuid::nil(), "invalid input");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn nist_si11_unauthorized_returns_401() {
        let err = ApiError::unauthorized(Uuid::nil());
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.message, "authentication required");
    }

    #[test]
    fn nist_si11_forbidden_returns_403() {
        let err = ApiError::forbidden(Uuid::nil());
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.message, "access denied");
    }

    #[test]
    fn nist_si11_not_found_returns_404() {
        let err = ApiError::not_found(Uuid::nil());
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn too_many_requests_includes_retry_after() {
        let err = ApiError::too_many_requests(Uuid::nil(), 30);
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(err.message.contains("30"));
    }

    #[test]
    fn api_error_display_includes_request_id() {
        let id = Uuid::new_v4();
        let err = ApiError::bad_request(id, "bad");
        let display = format!("{err}");
        assert!(display.contains(&id.to_string()));
    }
}
