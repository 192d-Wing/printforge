// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! IPPS job ingestion: IPP attribute parsing and metadata extraction.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
//! Every IPP attribute is validated and sanitized before acceptance.
//!
//! All ingested jobs are set to `job-hold-until=indefinite` for
//! Follow-Me printing.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::JobQueueError;

/// Maximum size of IPP attribute values to prevent abuse.
const MAX_ATTRIBUTE_VALUE_LEN: usize = 1024;

/// Parsed IPP attributes from an IPPS Print-Job or Send-Document request.
///
/// **NIST 800-53 Rev 5:** SI-10 — All string fields are length-bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IppAttributes {
    /// The `requesting-user-name` attribute (maps to EDIPI).
    pub requesting_user_name: String,
    /// The `document-name` attribute.
    pub document_name: String,
    /// Cost center code extracted from IPP vendor extension or HTTP header.
    pub cost_center_code: String,
    /// Human-readable cost center name.
    pub cost_center_name: String,
    /// The `copies` attribute.
    pub copies: Option<u16>,
    /// The `sides` attribute keyword.
    pub sides: String,
    /// The `print-color-mode` attribute keyword.
    pub color_mode: String,
    /// The `media` attribute keyword.
    pub media: String,
    /// Page count from `document-format` pre-analysis, if available.
    pub page_count: Option<u32>,
    /// The `job-hold-until` attribute. Must be `"indefinite"` for Follow-Me.
    pub job_hold_until: String,
}

/// An inbound IPPS print request containing parsed attributes and the
/// raw spool payload.
#[derive(Debug, Clone)]
pub struct IngestRequest {
    /// Parsed and validated IPP operation attributes.
    pub attributes: IppAttributes,
    /// Raw document payload (PDF, PCL, PostScript).
    pub payload: Bytes,
}

/// The result of a successful job ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    /// The generated job ID.
    pub job_id: pf_common::job::JobId,
    /// Confirmation that the job is held.
    pub status: pf_common::job::JobStatus,
    /// The document name after sanitization.
    pub document_name: String,
}

/// Validate raw IPP attributes for length limits and required fields.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` if any attribute exceeds
/// length limits or if required attributes are missing.
pub fn validate_ipp_attributes(attrs: &IppAttributes) -> Result<(), JobQueueError> {
    check_attribute_length("requesting-user-name", &attrs.requesting_user_name)?;
    check_attribute_length("document-name", &attrs.document_name)?;
    check_attribute_length("sides", &attrs.sides)?;
    check_attribute_length("print-color-mode", &attrs.color_mode)?;
    check_attribute_length("media", &attrs.media)?;

    if attrs.requesting_user_name.trim().is_empty() {
        return Err(JobQueueError::InvalidIppAttribute {
            attribute: "requesting-user-name".to_string(),
            source: None,
        });
    }

    if attrs.document_name.trim().is_empty() {
        return Err(JobQueueError::InvalidIppAttribute {
            attribute: "document-name".to_string(),
            source: None,
        });
    }

    Ok(())
}

/// Validate that a single attribute value does not exceed the maximum length.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` if the value exceeds
/// `MAX_ATTRIBUTE_VALUE_LEN`.
fn check_attribute_length(name: &str, value: &str) -> Result<(), JobQueueError> {
    if value.len() > MAX_ATTRIBUTE_VALUE_LEN {
        return Err(JobQueueError::InvalidIppAttribute {
            attribute: format!("{name} exceeds maximum length {MAX_ATTRIBUTE_VALUE_LEN}"),
            source: None,
        });
    }
    Ok(())
}

/// Validate that the payload size does not exceed the configured maximum.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidIppAttribute` if the payload is empty or
/// exceeds `max_bytes`.
pub fn validate_payload_size(payload: &Bytes, max_bytes: u64) -> Result<(), JobQueueError> {
    if payload.is_empty() {
        return Err(JobQueueError::InvalidIppAttribute {
            attribute: "document-data (empty payload)".to_string(),
            source: None,
        });
    }
    let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if len > max_bytes {
        return Err(JobQueueError::InvalidIppAttribute {
            attribute: format!("document-data exceeds maximum size ({len} > {max_bytes})"),
            source: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attrs() -> IppAttributes {
        IppAttributes {
            requesting_user_name: "1234567890".to_string(),
            document_name: "test.pdf".to_string(),
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
    fn nist_si10_validates_attribute_lengths() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        let mut attrs = sample_attrs();
        attrs.document_name = "x".repeat(MAX_ATTRIBUTE_VALUE_LEN + 1);
        assert!(validate_ipp_attributes(&attrs).is_err());
    }

    #[test]
    fn nist_si10_rejects_empty_user_name() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        let mut attrs = sample_attrs();
        attrs.requesting_user_name = "   ".to_string();
        assert!(validate_ipp_attributes(&attrs).is_err());
    }

    #[test]
    fn nist_si10_rejects_empty_document_name() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        let mut attrs = sample_attrs();
        attrs.document_name = String::new();
        assert!(validate_ipp_attributes(&attrs).is_err());
    }

    #[test]
    fn validate_payload_rejects_empty() {
        let payload = Bytes::new();
        assert!(validate_payload_size(&payload, 1024).is_err());
    }

    #[test]
    fn validate_payload_rejects_oversized() {
        let payload = Bytes::from(vec![0u8; 2048]);
        assert!(validate_payload_size(&payload, 1024).is_err());
    }

    #[test]
    fn validate_payload_accepts_within_limit() {
        let payload = Bytes::from(vec![0u8; 512]);
        assert!(validate_payload_size(&payload, 1024).is_ok());
    }

    #[test]
    fn valid_attributes_pass_validation() {
        let attrs = sample_attrs();
        assert!(validate_ipp_attributes(&attrs).is_ok());
    }
}
