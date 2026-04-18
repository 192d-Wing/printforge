// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `JobMetadata` construction from IPP attributes.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
//! All IPP attribute values are validated and sanitized before being stored.

use chrono::Utc;
use pf_common::error::ValidationError;
use pf_common::identity::Edipi;
use pf_common::job::{
    ColorMode, CostCenter, JobId, JobMetadata, JobStatus, MediaSize, PrintOptions, Sides,
};

use crate::error::JobQueueError;
use crate::ingestion::IppAttributes;

/// Maximum document name length to prevent abuse.
const MAX_DOCUMENT_NAME_LEN: usize = 255;

/// Builds a validated `JobMetadata` from parsed IPP attributes.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
///
/// # Errors
///
/// Returns `JobQueueError::Validation` if required fields are missing or invalid.
/// Returns `JobQueueError::InvalidIppAttribute` if an IPP attribute value is
/// unparseable.
pub fn build_job_metadata(attrs: &IppAttributes) -> Result<JobMetadata, JobQueueError> {
    let owner = Edipi::new(&attrs.requesting_user_name)?;

    let document_name = sanitize_document_name(&attrs.document_name)?;

    let cost_center = CostCenter::new(&attrs.cost_center_code, &attrs.cost_center_name)?;

    let options = PrintOptions {
        copies: parse_copies(attrs.copies)?,
        sides: parse_sides(&attrs.sides)?,
        color: parse_color_mode(&attrs.color_mode)?,
        media: parse_media_size(&attrs.media)?,
    };

    Ok(JobMetadata {
        id: JobId::generate(),
        owner,
        document_name,
        status: JobStatus::Held,
        options,
        cost_center,
        page_count: attrs.page_count,
        submitted_at: Utc::now(),
        released_at: None,
        completed_at: None,
    })
}

/// Sanitize a document name, truncating to `MAX_DOCUMENT_NAME_LEN` and
/// stripping control characters.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
///
/// # Errors
///
/// Returns `ValidationError::RequiredField` if the name is empty after sanitization.
fn sanitize_document_name(raw: &str) -> Result<String, ValidationError> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DOCUMENT_NAME_LEN)
        .collect();
    let trimmed = cleaned.trim().to_string();
    if trimmed.is_empty() {
        return Err(ValidationError::RequiredField {
            field: "document-name".to_string(),
        });
    }
    Ok(trimmed)
}

/// Parse and validate the copies value from the IPP attribute.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` if copies is zero.
fn parse_copies(copies: Option<u16>) -> Result<u16, JobQueueError> {
    let c = copies.unwrap_or(1);
    if c == 0 {
        return Err(JobQueueError::InvalidIppAttribute {
            attribute: "copies".to_string(),
            source: None,
        });
    }
    Ok(c)
}

/// Parse the `sides` IPP attribute keyword.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` for unrecognised values.
fn parse_sides(raw: &str) -> Result<Sides, JobQueueError> {
    match raw {
        "one-sided" => Ok(Sides::OneSided),
        "two-sided-long-edge" | "" => Ok(Sides::TwoSidedLongEdge),
        "two-sided-short-edge" => Ok(Sides::TwoSidedShortEdge),
        other => Err(JobQueueError::InvalidIppAttribute {
            attribute: format!("sides: {other}"),
            source: None,
        }),
    }
}

/// Parse the `print-color-mode` IPP attribute keyword.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` for unrecognised values.
fn parse_color_mode(raw: &str) -> Result<ColorMode, JobQueueError> {
    match raw {
        "color" => Ok(ColorMode::Color),
        "monochrome" | "grayscale" | "" => Ok(ColorMode::Grayscale),
        "auto" => Ok(ColorMode::AutoDetect),
        other => Err(JobQueueError::InvalidIppAttribute {
            attribute: format!("print-color-mode: {other}"),
            source: None,
        }),
    }
}

/// Parse the `media` IPP attribute keyword.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` for unrecognised values.
fn parse_media_size(raw: &str) -> Result<MediaSize, JobQueueError> {
    match raw {
        "na_letter_8.5x11in" | "letter" | "" => Ok(MediaSize::Letter),
        "na_legal_8.5x14in" | "legal" => Ok(MediaSize::Legal),
        "na_ledger_11x17in" | "ledger" => Ok(MediaSize::Ledger),
        "iso_a4_210x297mm" | "a4" => Ok(MediaSize::A4),
        "iso_a3_297x420mm" | "a3" => Ok(MediaSize::A3),
        other => Err(JobQueueError::InvalidIppAttribute {
            attribute: format!("media: {other}"),
            source: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attrs() -> IppAttributes {
        IppAttributes {
            requesting_user_name: "1234567890".to_string(),
            document_name: "test-document.pdf".to_string(),
            cost_center_code: "CC-001".to_string(),
            cost_center_name: "Test Unit".to_string(),
            copies: Some(1),
            sides: "two-sided-long-edge".to_string(),
            color_mode: "monochrome".to_string(),
            media: "na_letter_8.5x11in".to_string(),
            page_count: Some(5),
            job_hold_until: "indefinite".to_string(),
        }
    }

    #[test]
    fn nist_si10_build_metadata_validates_edipi() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        let mut attrs = sample_attrs();
        attrs.requesting_user_name = "INVALID".to_string();
        let result = build_job_metadata(&attrs);
        assert!(result.is_err());
    }

    #[test]
    fn nist_si10_build_metadata_rejects_empty_document_name() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        let mut attrs = sample_attrs();
        attrs.document_name = "   ".to_string();
        let result = build_job_metadata(&attrs);
        assert!(result.is_err());
    }

    #[test]
    fn build_metadata_strips_control_characters() {
        let mut attrs = sample_attrs();
        attrs.document_name = "test\x00doc\x1F.pdf".to_string();
        let meta = build_job_metadata(&attrs).unwrap();
        assert_eq!(meta.document_name, "testdoc.pdf");
    }

    #[test]
    fn build_metadata_defaults_to_held() {
        let attrs = sample_attrs();
        let meta = build_job_metadata(&attrs).unwrap();
        assert_eq!(meta.status, JobStatus::Held);
    }

    #[test]
    fn parse_copies_rejects_zero() {
        assert!(parse_copies(Some(0)).is_err());
    }

    #[test]
    fn parse_copies_defaults_to_one() {
        assert_eq!(parse_copies(None).unwrap(), 1);
    }

    #[test]
    fn parse_sides_all_variants() {
        assert_eq!(parse_sides("one-sided").unwrap(), Sides::OneSided);
        assert_eq!(
            parse_sides("two-sided-long-edge").unwrap(),
            Sides::TwoSidedLongEdge
        );
        assert_eq!(
            parse_sides("two-sided-short-edge").unwrap(),
            Sides::TwoSidedShortEdge
        );
        assert!(parse_sides("invalid").is_err());
    }

    #[test]
    fn parse_color_mode_all_variants() {
        assert_eq!(parse_color_mode("color").unwrap(), ColorMode::Color);
        assert_eq!(
            parse_color_mode("monochrome").unwrap(),
            ColorMode::Grayscale
        );
        assert_eq!(parse_color_mode("auto").unwrap(), ColorMode::AutoDetect);
        assert!(parse_color_mode("invalid").is_err());
    }

    #[test]
    fn parse_media_size_all_variants() {
        assert_eq!(
            parse_media_size("na_letter_8.5x11in").unwrap(),
            MediaSize::Letter
        );
        assert_eq!(
            parse_media_size("na_legal_8.5x14in").unwrap(),
            MediaSize::Legal
        );
        assert_eq!(parse_media_size("iso_a4_210x297mm").unwrap(), MediaSize::A4);
        assert!(parse_media_size("invalid").is_err());
    }
}
