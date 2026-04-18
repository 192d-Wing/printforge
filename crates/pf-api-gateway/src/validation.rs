// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Request body validation helpers and size limit enforcement.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use uuid::Uuid;

/// Maximum body size for standard API requests (1 MiB).
pub const DEFAULT_BODY_LIMIT: usize = 1_048_576;

/// Maximum body size for job upload requests (50 MiB).
pub const UPLOAD_BODY_LIMIT: usize = 52_428_800;

/// A validation error that can be returned from request extractors.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
#[derive(Debug)]
pub struct ValidationRejection {
    /// The request ID for log correlation.
    pub request_id: Uuid,
    /// Fields that failed validation.
    pub errors: Vec<FieldError>,
}

/// A single field-level validation error.
#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    /// The field name that failed validation.
    pub field: String,
    /// A human-readable description of the constraint that was violated.
    pub message: String,
}

impl IntoResponse for ValidationRejection {
    fn into_response(self) -> Response {
        let body = ValidationErrorBody {
            request_id: self.request_id.to_string(),
            status: 400,
            message: "validation failed".to_string(),
            errors: self.errors,
        };
        (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
    }
}

/// Response body for validation errors, extending the base `ApiErrorBody` with
/// field-level details.
#[derive(Debug, Serialize)]
struct ValidationErrorBody {
    request_id: String,
    status: u16,
    message: String,
    errors: Vec<FieldError>,
}

/// Validate that a string field is not empty.
///
/// # Errors
///
/// Returns a `FieldError` if the value is empty or whitespace-only.
pub fn require_non_empty(field: &str, value: &str) -> Result<(), FieldError> {
    if value.trim().is_empty() {
        return Err(FieldError {
            field: field.to_string(),
            message: format!("'{field}' must not be empty"),
        });
    }
    Ok(())
}

/// Validate that a string field does not exceed the maximum length.
///
/// # Errors
///
/// Returns a `FieldError` if the value exceeds `max_len` bytes.
pub fn require_max_length(field: &str, value: &str, max_len: usize) -> Result<(), FieldError> {
    if value.len() > max_len {
        return Err(FieldError {
            field: field.to_string(),
            message: format!("'{field}' must not exceed {max_len} characters"),
        });
    }
    Ok(())
}

/// Validate that a numeric value is within an inclusive range.
///
/// # Errors
///
/// Returns a `FieldError` if the value is outside `[min, max]`.
pub fn require_range(field: &str, value: i64, min: i64, max: i64) -> Result<(), FieldError> {
    if value < min || value > max {
        return Err(FieldError {
            field: field.to_string(),
            message: format!("'{field}' must be between {min} and {max}"),
        });
    }
    Ok(())
}

/// Collect multiple validation results into a single `ValidationRejection`.
///
/// # Errors
///
/// Returns `Err(ValidationRejection)` if any of the results contain errors.
pub fn collect_errors(
    request_id: Uuid,
    results: Vec<Result<(), FieldError>>,
) -> Result<(), ValidationRejection> {
    let errors: Vec<FieldError> = results.into_iter().filter_map(Result::err).collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationRejection { request_id, errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_si10_require_non_empty_rejects_blank() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        assert!(require_non_empty("name", "").is_err());
        assert!(require_non_empty("name", "   ").is_err());
    }

    #[test]
    fn nist_si10_require_non_empty_accepts_value() {
        assert!(require_non_empty("name", "John").is_ok());
    }

    #[test]
    fn nist_si10_require_max_length_rejects_too_long() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        assert!(require_max_length("field", "abcdef", 3).is_err());
    }

    #[test]
    fn require_max_length_accepts_within_limit() {
        assert!(require_max_length("field", "abc", 3).is_ok());
    }

    #[test]
    fn require_range_accepts_within_bounds() {
        assert!(require_range("copies", 5, 1, 100).is_ok());
    }

    #[test]
    fn require_range_rejects_out_of_bounds() {
        assert!(require_range("copies", 0, 1, 100).is_err());
        assert!(require_range("copies", 101, 1, 100).is_err());
    }

    #[test]
    fn collect_errors_returns_ok_when_all_pass() {
        let results = vec![
            require_non_empty("a", "ok"),
            require_max_length("b", "ok", 10),
        ];
        assert!(collect_errors(Uuid::nil(), results).is_ok());
    }

    #[test]
    fn collect_errors_gathers_all_failures() {
        let results = vec![
            require_non_empty("a", ""),
            require_non_empty("b", ""),
            require_non_empty("c", "valid"),
        ];
        let err = collect_errors(Uuid::nil(), results).unwrap_err();
        assert_eq!(err.errors.len(), 2);
    }

    #[test]
    fn field_error_serializes_to_json() {
        let err = FieldError {
            field: "name".to_string(),
            message: "must not be empty".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("name"));
        assert!(json.contains("must not be empty"));
    }

    #[test]
    fn body_limits_are_correct() {
        assert_eq!(DEFAULT_BODY_LIMIT, 1_048_576);
        assert_eq!(UPLOAD_BODY_LIMIT, 52_428_800);
    }
}
