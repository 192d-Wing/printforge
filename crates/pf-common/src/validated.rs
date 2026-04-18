// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Newtype validation utilities.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
//!
//! This module re-exports the validated newtypes and provides shared
//! validation helpers. Each domain newtype (`Edipi`, `JobId`, `PrinterId`,
//! `CostCenter`) validates input in its constructor and returns `Result`.

use crate::error::ValidationError;

/// Validate that a string field is non-empty and within a maximum length.
///
/// # Errors
///
/// Returns `ValidationError::RequiredField` if blank, or `ValidationError::TooLong` if
/// the trimmed value exceeds `max_len`.
pub fn validate_non_empty(field: &str, value: &str, max_len: usize) -> Result<(), ValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::RequiredField {
            field: field.to_string(),
        });
    }
    if trimmed.len() > max_len {
        return Err(ValidationError::TooLong {
            field: field.to_string(),
            max: max_len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_non_empty_accepts_valid_input() {
        assert!(validate_non_empty("name", "hello", 100).is_ok());
    }

    #[test]
    fn validate_non_empty_rejects_blank() {
        assert!(validate_non_empty("name", "   ", 100).is_err());
    }

    #[test]
    fn validate_non_empty_rejects_too_long() {
        assert!(validate_non_empty("name", "abcdef", 5).is_err());
    }
}
