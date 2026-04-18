// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! WPP / `IPP` Everywhere compatibility layer.
//!
//! Provides the `Mopria`-required printer attributes for Windows Print
//! Protocol (WPP) and `IPP` Everywhere (PWG 5100.14) auto-discovery.
//! These attributes are returned in Get-Printer-Attributes responses so
//! that Windows 11 WPP clients and macOS/Linux CUPS clients can discover
//! and use the `PrintForge` virtual queue without a custom driver.

use crate::ipp_parser::AttributeGroupTag;
use crate::ipp_response::{ResponseAttribute, ResponseAttributeGroup};

/// Printer URI scheme used by the `IPPS` endpoint.
pub const PRINTER_URI_SCHEME: &str = "ipps";

/// Default printer-info string advertised to clients.
pub const DEFAULT_PRINTER_INFO: &str = "PrintForge Follow-Me Virtual Printer";

/// Default printer-make-and-model for `IPP` Everywhere discovery.
pub const DEFAULT_PRINTER_MAKE_AND_MODEL: &str = "PrintForge Virtual Printer";

/// `IPP` versions advertised as supported.
pub const IPP_VERSIONS_SUPPORTED: &[&str] = &["1.1", "2.0"];

/// Document formats advertised as supported.
pub const DOCUMENT_FORMATS_SUPPORTED: &[&str] = &[
    "application/pdf",
    "image/pwg-raster",
    "application/vnd.hp-pcl",
    "application/octet-stream",
];

/// Operations advertised as supported by this endpoint.
pub const OPERATIONS_SUPPORTED: &[u16] = &[
    0x0002, // Print-Job
    0x0004, // Validate-Job
    0x0005, // Create-Job
    0x0006, // Send-Document
    0x0008, // Cancel-Job
    0x000A, // Get-Jobs
    0x000B, // Get-Printer-Attributes
];

/// Sides values advertised as supported.
pub const SIDES_SUPPORTED: &[&str] = &["one-sided", "two-sided-long-edge", "two-sided-short-edge"];

/// Media sizes advertised as supported.
pub const MEDIA_SUPPORTED: &[&str] = &[
    "na_letter_8.5x11in",
    "na_legal_8.5x14in",
    "na_ledger_11x17in",
    "iso_a4_210x297mm",
    "iso_a3_297x420mm",
];

/// Build the printer-attributes group for a Get-Printer-Attributes response.
///
/// Includes all attributes required by `IPP` Everywhere / `Mopria` / WPP
/// for driverless discovery.
#[must_use]
pub fn build_printer_attributes(printer_uri: &str) -> ResponseAttributeGroup {
    let mut attrs = vec![
        // Required printer identification
        ResponseAttribute::uri("printer-uri-supported", printer_uri),
        ResponseAttribute::keyword("uri-security-supported", "tls"),
        ResponseAttribute::keyword("uri-authentication-supported", "requesting-user-name"),
        ResponseAttribute::text("printer-name", DEFAULT_PRINTER_INFO),
        ResponseAttribute::text("printer-info", DEFAULT_PRINTER_INFO),
        ResponseAttribute::text("printer-make-and-model", DEFAULT_PRINTER_MAKE_AND_MODEL),
        // Printer state: always "idle" (virtual queue accepts everything)
        // printer-state enum: 3 = idle
        ResponseAttribute::enum_value("printer-state", 3),
        ResponseAttribute::keyword("printer-state-reasons", "none"),
        ResponseAttribute::boolean("printer-is-accepting-jobs", true),
    ];

    // IPP version support
    for version in IPP_VERSIONS_SUPPORTED {
        attrs.push(ResponseAttribute::keyword(
            "ipp-versions-supported",
            *version,
        ));
    }

    // Supported operations (as enum/integer values)
    for &op_id in OPERATIONS_SUPPORTED {
        attrs.push(ResponseAttribute::enum_value(
            "operations-supported",
            i32::from(op_id),
        ));
    }

    // Document formats
    for fmt in DOCUMENT_FORMATS_SUPPORTED {
        attrs.push(ResponseAttribute::mime_media_type(
            "document-format-supported",
            *fmt,
        ));
    }
    attrs.push(ResponseAttribute::mime_media_type(
        "document-format-default",
        "application/pdf",
    ));

    // Sides
    for side in SIDES_SUPPORTED {
        attrs.push(ResponseAttribute::keyword("sides-supported", *side));
    }
    attrs.push(ResponseAttribute::keyword(
        "sides-default",
        "two-sided-long-edge",
    ));

    // Media
    for media in MEDIA_SUPPORTED {
        attrs.push(ResponseAttribute::keyword("media-supported", *media));
    }
    attrs.push(ResponseAttribute::keyword(
        "media-default",
        "na_letter_8.5x11in",
    ));

    // Color
    attrs.push(ResponseAttribute::keyword(
        "print-color-mode-supported",
        "color",
    ));
    attrs.push(ResponseAttribute::keyword(
        "print-color-mode-supported",
        "monochrome",
    ));
    attrs.push(ResponseAttribute::keyword(
        "print-color-mode-supported",
        "auto",
    ));
    attrs.push(ResponseAttribute::keyword(
        "print-color-mode-default",
        "monochrome",
    ));

    // Copies
    attrs.push(ResponseAttribute::integer("copies-default", 1));

    // Charset and language
    attrs.push(ResponseAttribute::charset("charset-configured", "utf-8"));
    attrs.push(ResponseAttribute::charset("charset-supported", "utf-8"));
    attrs.push(ResponseAttribute::natural_language(
        "natural-language-configured",
        "en",
    ));

    // IPP Everywhere / Mopria markers
    attrs.push(ResponseAttribute::keyword(
        "ipp-features-supported",
        "ipp-everywhere",
    ));

    ResponseAttributeGroup {
        tag: AttributeGroupTag::PrinterAttributes,
        attributes: attrs,
    }
}

/// Check if the printer-attributes group contains all `Mopria`-required attributes.
///
/// Returns a list of missing attribute names. An empty list means the
/// response is WPP-compatible.
#[must_use]
pub fn validate_mopria_required_attributes(group: &ResponseAttributeGroup) -> Vec<&'static str> {
    const REQUIRED: &[&str] = &[
        "printer-uri-supported",
        "uri-security-supported",
        "printer-name",
        "printer-state",
        "printer-is-accepting-jobs",
        "ipp-versions-supported",
        "operations-supported",
        "document-format-supported",
        "charset-configured",
        "natural-language-configured",
    ];

    REQUIRED
        .iter()
        .filter(|&&name| !group.attributes.iter().any(|a| a.name == name))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printer_attributes_contains_uri() {
        let group = build_printer_attributes("ipps://printforge.example.mil/ipp/print");
        let uri_attr = group
            .attributes
            .iter()
            .find(|a| a.name == "printer-uri-supported")
            .expect("printer-uri-supported missing");
        let value = String::from_utf8_lossy(&uri_attr.value);
        assert!(value.contains("ipps://"));
    }

    #[test]
    fn printer_attributes_has_tls_security() {
        let group = build_printer_attributes("ipps://test/ipp/print");
        let sec = group
            .attributes
            .iter()
            .find(|a| a.name == "uri-security-supported")
            .expect("uri-security-supported missing");
        assert_eq!(String::from_utf8_lossy(&sec.value), "tls");
    }

    #[test]
    fn wpp_mopria_required_attributes_present() {
        let group = build_printer_attributes("ipps://test/ipp/print");
        let missing = validate_mopria_required_attributes(&group);
        assert!(
            missing.is_empty(),
            "missing Mopria-required attributes: {missing:?}"
        );
    }

    #[test]
    fn document_formats_include_pdf() {
        let group = build_printer_attributes("ipps://test/ipp/print");
        let has_pdf = group.attributes.iter().any(|a| {
            a.name == "document-format-supported" && a.value == b"application/pdf".to_vec()
        });
        assert!(has_pdf, "PDF format not advertised");
    }

    #[test]
    fn nist_sc8_security_is_tls_only() {
        // NIST 800-53 Rev 5: SC-8 — Transmission Confidentiality
        // Evidence: the advertised uri-security-supported is always "tls"
        let group = build_printer_attributes("ipps://test/ipp/print");
        let security_attrs: Vec<_> = group
            .attributes
            .iter()
            .filter(|a| a.name == "uri-security-supported")
            .collect();
        assert_eq!(security_attrs.len(), 1);
        assert_eq!(String::from_utf8_lossy(&security_attrs[0].value), "tls");
    }
}
