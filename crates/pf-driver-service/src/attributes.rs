// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IPP` attribute extraction, validation, and mapping to `JobMetadata`.
//!
//! All `IPP` attributes are treated as untrusted input. Each attribute is
//! validated against expected types and ranges before being mapped to the
//! strongly-typed `PrintOptions` used by `PrintForge`.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation

use pf_common::job::{ColorMode, MediaSize, PrintOptions, Sides};

use crate::error::DriverServiceError;
use crate::ipp_parser::{IppAttributeGroup, ValueTag};

/// Maximum length for the `job-name` attribute (bytes).
const MAX_JOB_NAME_LEN: usize = 255;

/// Maximum length for the `requesting-user-name` attribute (bytes).
const MAX_USER_NAME_LEN: usize = 255;

/// Extract and validate the `requesting-user-name` attribute.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
///
/// # Errors
///
/// Returns `DriverServiceError::InvalidAttribute` if the attribute is missing,
/// empty, or exceeds the maximum length.
pub fn extract_requesting_user_name(
    operation_attrs: &IppAttributeGroup,
) -> Result<String, DriverServiceError> {
    let attr = operation_attrs
        .find_attribute("requesting-user-name")
        .ok_or_else(|| DriverServiceError::InvalidAttribute {
            name: "requesting-user-name".to_string(),
            reason: "attribute is required".to_string(),
        })?;

    if attr.value_tag != ValueTag::NameWithoutLanguage
        && attr.value_tag != ValueTag::TextWithoutLanguage
    {
        return Err(DriverServiceError::InvalidAttribute {
            name: "requesting-user-name".to_string(),
            reason: format!("expected name or text tag, got {:?}", attr.value_tag),
        });
    }

    let name = String::from_utf8_lossy(&attr.value).to_string();
    let trimmed = name.trim().to_string();

    if trimmed.is_empty() {
        return Err(DriverServiceError::InvalidAttribute {
            name: "requesting-user-name".to_string(),
            reason: "value must not be empty".to_string(),
        });
    }

    if trimmed.len() > MAX_USER_NAME_LEN {
        return Err(DriverServiceError::InvalidAttribute {
            name: "requesting-user-name".to_string(),
            reason: format!("exceeds maximum length of {MAX_USER_NAME_LEN}"),
        });
    }

    Ok(trimmed)
}

/// Extract and validate the `job-name` attribute. Returns a default if absent.
///
/// # Errors
///
/// Returns `DriverServiceError::InvalidAttribute` if the attribute value
/// exceeds the maximum length.
pub fn extract_job_name(operation_attrs: &IppAttributeGroup) -> Result<String, DriverServiceError> {
    let Some(attr) = operation_attrs.find_attribute("job-name") else {
        return Ok("Untitled".to_string());
    };

    let name = String::from_utf8_lossy(&attr.value).to_string();
    let trimmed = name.trim().to_string();

    if trimmed.len() > MAX_JOB_NAME_LEN {
        return Err(DriverServiceError::InvalidAttribute {
            name: "job-name".to_string(),
            reason: format!("exceeds maximum length of {MAX_JOB_NAME_LEN}"),
        });
    }

    if trimmed.is_empty() {
        return Ok("Untitled".to_string());
    }

    Ok(trimmed)
}

/// Extract and validate the `document-format` attribute.
///
/// # Errors
///
/// Returns `DriverServiceError::InvalidAttribute` if the attribute is missing
/// or has an unexpected value tag.
pub fn extract_document_format(
    operation_attrs: &IppAttributeGroup,
) -> Result<String, DriverServiceError> {
    let attr = operation_attrs
        .find_attribute("document-format")
        .ok_or_else(|| DriverServiceError::InvalidAttribute {
            name: "document-format".to_string(),
            reason: "attribute is required".to_string(),
        })?;

    if attr.value_tag != ValueTag::MimeMediaType {
        return Err(DriverServiceError::InvalidAttribute {
            name: "document-format".to_string(),
            reason: format!("expected mimeMediaType tag, got {:?}", attr.value_tag),
        });
    }

    Ok(String::from_utf8_lossy(&attr.value).to_string())
}

/// Parse the `sides` `IPP` attribute keyword into a `Sides` value.
///
/// Defaults to `Sides::TwoSidedLongEdge` if the attribute is absent.
#[must_use]
pub fn extract_sides(job_attrs: Option<&IppAttributeGroup>) -> Sides {
    let Some(group) = job_attrs else {
        return Sides::TwoSidedLongEdge;
    };
    let Some(attr) = group.find_attribute("sides") else {
        return Sides::TwoSidedLongEdge;
    };

    let value = String::from_utf8_lossy(&attr.value);
    match value.as_ref() {
        "one-sided" => Sides::OneSided,
        "two-sided-long-edge" => Sides::TwoSidedLongEdge,
        "two-sided-short-edge" => Sides::TwoSidedShortEdge,
        _ => {
            tracing::warn!(
                attribute = "sides",
                value = %value,
                "unknown sides value, defaulting to two-sided-long-edge"
            );
            Sides::TwoSidedLongEdge
        }
    }
}

/// Parse the `print-color-mode` `IPP` attribute keyword into a `ColorMode`.
///
/// Defaults to `ColorMode::Grayscale` if the attribute is absent.
#[must_use]
pub fn extract_color_mode(job_attrs: Option<&IppAttributeGroup>) -> ColorMode {
    let Some(group) = job_attrs else {
        return ColorMode::Grayscale;
    };
    let Some(attr) = group.find_attribute("print-color-mode") else {
        return ColorMode::Grayscale;
    };

    let value = String::from_utf8_lossy(&attr.value);
    match value.as_ref() {
        "color" => ColorMode::Color,
        "monochrome" => ColorMode::Grayscale,
        "auto" => ColorMode::AutoDetect,
        _ => {
            tracing::warn!(
                attribute = "print-color-mode",
                value = %value,
                "unknown color mode, defaulting to grayscale"
            );
            ColorMode::Grayscale
        }
    }
}

/// Parse the `media` `IPP` attribute keyword into a `MediaSize`.
///
/// Defaults to `MediaSize::Letter` if the attribute is absent.
#[must_use]
pub fn extract_media_size(job_attrs: Option<&IppAttributeGroup>) -> MediaSize {
    let Some(group) = job_attrs else {
        return MediaSize::Letter;
    };
    let Some(attr) = group.find_attribute("media") else {
        return MediaSize::Letter;
    };

    let value = String::from_utf8_lossy(&attr.value);
    match value.as_ref() {
        "na_letter_8.5x11in" | "iso_a_letter" | "letter" => MediaSize::Letter,
        "na_legal_8.5x14in" | "legal" => MediaSize::Legal,
        "na_ledger_11x17in" | "ledger" => MediaSize::Ledger,
        "iso_a4_210x297mm" | "a4" => MediaSize::A4,
        "iso_a3_297x420mm" | "a3" => MediaSize::A3,
        _ => {
            tracing::warn!(
                attribute = "media",
                value = %value,
                "unknown media size, defaulting to letter"
            );
            MediaSize::Letter
        }
    }
}

/// Parse the `copies` `IPP` attribute into a `u16`.
///
/// Defaults to 1 if the attribute is absent. Values are clamped to the
/// range 1..=999.
#[must_use]
pub fn extract_copies(job_attrs: Option<&IppAttributeGroup>) -> u16 {
    let Some(group) = job_attrs else {
        return 1;
    };
    let Some(attr) = group.find_attribute("copies") else {
        return 1;
    };

    if attr.value.len() != 4 {
        tracing::warn!(
            attribute = "copies",
            len = attr.value.len(),
            "invalid copies value length, defaulting to 1"
        );
        return 1;
    }

    let raw = i32::from_be_bytes([attr.value[0], attr.value[1], attr.value[2], attr.value[3]]);

    #[allow(clippy::cast_sign_loss)]
    let copies = raw.clamp(1, 999) as u16;
    copies
}

/// Build `PrintOptions` from validated `IPP` job attributes.
#[must_use]
pub fn build_print_options(job_attrs: Option<&IppAttributeGroup>) -> PrintOptions {
    PrintOptions {
        copies: extract_copies(job_attrs),
        sides: extract_sides(job_attrs),
        color: extract_color_mode(job_attrs),
        media: extract_media_size(job_attrs),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::ipp_parser::{AttributeGroupTag, IppAttribute, IppAttributeGroup};

    fn make_op_group(attrs: Vec<IppAttribute>) -> IppAttributeGroup {
        IppAttributeGroup {
            tag: AttributeGroupTag::OperationAttributes,
            attributes: attrs,
        }
    }

    fn make_job_group(attrs: Vec<IppAttribute>) -> IppAttributeGroup {
        IppAttributeGroup {
            tag: AttributeGroupTag::JobAttributes,
            attributes: attrs,
        }
    }

    #[test]
    fn nist_si10_requesting_user_name_required() {
        let group = make_op_group(vec![]);
        assert!(extract_requesting_user_name(&group).is_err());
    }

    #[test]
    fn nist_si10_requesting_user_name_rejects_empty() {
        let group = make_op_group(vec![IppAttribute {
            name: "requesting-user-name".to_string(),
            value_tag: ValueTag::NameWithoutLanguage,
            value: Bytes::from_static(b"   "),
        }]);
        assert!(extract_requesting_user_name(&group).is_err());
    }

    #[test]
    fn nist_si10_requesting_user_name_rejects_too_long() {
        let long_name = "a".repeat(256);
        let group = make_op_group(vec![IppAttribute {
            name: "requesting-user-name".to_string(),
            value_tag: ValueTag::NameWithoutLanguage,
            value: Bytes::from(long_name),
        }]);
        assert!(extract_requesting_user_name(&group).is_err());
    }

    #[test]
    fn extracts_valid_user_name() {
        let group = make_op_group(vec![IppAttribute {
            name: "requesting-user-name".to_string(),
            value_tag: ValueTag::NameWithoutLanguage,
            value: Bytes::from_static(b"DOE.JOHN.Q.1234567890"),
        }]);
        let name = extract_requesting_user_name(&group).unwrap();
        assert_eq!(name, "DOE.JOHN.Q.1234567890");
    }

    #[test]
    fn job_name_defaults_to_untitled() {
        let group = make_op_group(vec![]);
        let name = extract_job_name(&group).unwrap();
        assert_eq!(name, "Untitled");
    }

    #[test]
    fn nist_si10_job_name_rejects_too_long() {
        let long = "x".repeat(256);
        let group = make_op_group(vec![IppAttribute {
            name: "job-name".to_string(),
            value_tag: ValueTag::NameWithoutLanguage,
            value: Bytes::from(long),
        }]);
        assert!(extract_job_name(&group).is_err());
    }

    #[test]
    fn sides_defaults_to_two_sided_long() {
        assert_eq!(extract_sides(None), Sides::TwoSidedLongEdge);
    }

    #[test]
    fn parses_one_sided() {
        let group = make_job_group(vec![IppAttribute {
            name: "sides".to_string(),
            value_tag: ValueTag::Keyword,
            value: Bytes::from_static(b"one-sided"),
        }]);
        assert_eq!(extract_sides(Some(&group)), Sides::OneSided);
    }

    #[test]
    fn color_mode_defaults_to_grayscale() {
        assert_eq!(extract_color_mode(None), ColorMode::Grayscale);
    }

    #[test]
    fn parses_color_mode() {
        let group = make_job_group(vec![IppAttribute {
            name: "print-color-mode".to_string(),
            value_tag: ValueTag::Keyword,
            value: Bytes::from_static(b"color"),
        }]);
        assert_eq!(extract_color_mode(Some(&group)), ColorMode::Color);
    }

    #[test]
    fn media_defaults_to_letter() {
        assert_eq!(extract_media_size(None), MediaSize::Letter);
    }

    #[test]
    fn copies_defaults_to_one() {
        assert_eq!(extract_copies(None), 1);
    }

    #[test]
    fn copies_clamped_to_999() {
        let group = make_job_group(vec![IppAttribute {
            name: "copies".to_string(),
            value_tag: ValueTag::Integer,
            value: Bytes::from(2000_i32.to_be_bytes().to_vec()),
        }]);
        assert_eq!(extract_copies(Some(&group)), 999);
    }

    #[test]
    fn copies_clamped_to_1_for_zero() {
        let group = make_job_group(vec![IppAttribute {
            name: "copies".to_string(),
            value_tag: ValueTag::Integer,
            value: Bytes::from(0_i32.to_be_bytes().to_vec()),
        }]);
        assert_eq!(extract_copies(Some(&group)), 1);
    }

    #[test]
    fn build_print_options_uses_defaults() {
        let opts = build_print_options(None);
        assert_eq!(opts.copies, 1);
        assert_eq!(opts.sides, Sides::TwoSidedLongEdge);
        assert_eq!(opts.color, ColorMode::Grayscale);
        assert_eq!(opts.media, MediaSize::Letter);
    }
}
