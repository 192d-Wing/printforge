// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IPP` response builder.
//!
//! Constructs well-formed `IPP` response messages with status codes and
//! attribute groups per RFC 8011.

use bytes::{BufMut, BytesMut};

use crate::ipp_parser::{AttributeGroupTag, IppVersion, ValueTag};

/// `IPP` status codes (RFC 8011 section 4.1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IppStatusCode {
    /// Successful completion (0x0000).
    SuccessfulOk,
    /// Successful with informational attributes (0x0001).
    SuccessfulOkIgnoredOrSubstitutedAttributes,
    /// Client sent a bad request (0x0400).
    ClientErrorBadRequest,
    /// Client is not authorized (0x0401).
    ClientErrorForbidden,
    /// Client is not authenticated (0x0402).
    ClientErrorNotAuthenticated,
    /// The requested operation is not supported (0x0405).
    ClientErrorOperationNotSupported,
    /// The document format is not supported (0x040A).
    ClientErrorDocumentFormatNotSupported,
    /// The request entity is too large (0x0408).
    ClientErrorRequestEntityTooLarge,
    /// Server encountered an internal error (0x0500).
    ServerErrorInternalError,
    /// The operation is not supported by this server (0x0501).
    ServerErrorOperationNotSupported,
    /// Server is temporarily unavailable (0x0503).
    ServerErrorServiceUnavailable,
}

impl IppStatusCode {
    /// Return the `u16` wire representation.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::SuccessfulOk => 0x0000,
            Self::SuccessfulOkIgnoredOrSubstitutedAttributes => 0x0001,
            Self::ClientErrorBadRequest => 0x0400,
            Self::ClientErrorForbidden => 0x0401,
            Self::ClientErrorNotAuthenticated => 0x0402,
            Self::ClientErrorOperationNotSupported => 0x0405,
            Self::ClientErrorDocumentFormatNotSupported => 0x040A,
            Self::ClientErrorRequestEntityTooLarge => 0x0408,
            Self::ServerErrorInternalError => 0x0500,
            Self::ServerErrorOperationNotSupported => 0x0501,
            Self::ServerErrorServiceUnavailable => 0x0503,
        }
    }

    /// Returns `true` if the status indicates success.
    #[must_use]
    pub fn is_success(self) -> bool {
        self.code() < 0x0400
    }
}

/// An attribute to include in a response attribute group.
#[derive(Debug, Clone)]
pub struct ResponseAttribute {
    /// Attribute name.
    pub name: String,
    /// Value-type tag.
    pub value_tag: ValueTag,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl ResponseAttribute {
    /// Create a keyword attribute.
    #[must_use]
    pub fn keyword(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::Keyword,
            value: value.into().into_bytes(),
        }
    }

    /// Create a text-without-language attribute.
    #[must_use]
    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::TextWithoutLanguage,
            value: value.into().into_bytes(),
        }
    }

    /// Create a name-without-language attribute.
    #[must_use]
    pub fn name_value(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::NameWithoutLanguage,
            value: value.into().into_bytes(),
        }
    }

    /// Create an integer attribute.
    #[must_use]
    pub fn integer(name: impl Into<String>, value: i32) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::Integer,
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// Create a URI attribute.
    #[must_use]
    pub fn uri(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::Uri,
            value: value.into().into_bytes(),
        }
    }

    /// Create a charset attribute.
    #[must_use]
    pub fn charset(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::Charset,
            value: value.into().into_bytes(),
        }
    }

    /// Create a natural-language attribute.
    #[must_use]
    pub fn natural_language(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::NaturalLanguage,
            value: value.into().into_bytes(),
        }
    }

    /// Create a MIME media-type attribute.
    #[must_use]
    pub fn mime_media_type(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::MimeMediaType,
            value: value.into().into_bytes(),
        }
    }

    /// Create an enum attribute (encoded as 4-byte big-endian integer).
    #[must_use]
    pub fn enum_value(name: impl Into<String>, value: i32) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::Enum,
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// Create a boolean attribute.
    #[must_use]
    pub fn boolean(name: impl Into<String>, value: bool) -> Self {
        Self {
            name: name.into(),
            value_tag: ValueTag::Boolean,
            value: vec![u8::from(value)],
        }
    }
}

/// A group of response attributes sharing a group tag.
#[derive(Debug, Clone)]
pub struct ResponseAttributeGroup {
    /// Group tag.
    pub tag: AttributeGroupTag,
    /// Attributes in this group.
    pub attributes: Vec<ResponseAttribute>,
}

/// Builder for constructing `IPP` response messages.
#[derive(Debug, Clone)]
pub struct IppResponseBuilder {
    version: IppVersion,
    status: IppStatusCode,
    request_id: u32,
    groups: Vec<ResponseAttributeGroup>,
}

impl IppResponseBuilder {
    /// Start building a response for the given request ID.
    #[must_use]
    pub fn new(status: IppStatusCode, request_id: u32) -> Self {
        Self {
            version: IppVersion::V2_0,
            status,
            request_id,
            groups: Vec::new(),
        }
    }

    /// Set the `IPP` version on the response (defaults to 2.0).
    #[must_use]
    pub fn version(mut self, version: IppVersion) -> Self {
        self.version = version;
        self
    }

    /// Add an attribute group to the response.
    #[must_use]
    pub fn add_group(mut self, group: ResponseAttributeGroup) -> Self {
        self.groups.push(group);
        self
    }

    /// Serialize the response into wire-format bytes.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(256);

        // Header: version (2) + status (2) + request-id (4)
        buf.put_u8(self.version.major);
        buf.put_u8(self.version.minor);
        buf.put_u16(self.status.code());
        buf.put_u32(self.request_id);

        // Attribute groups
        for group in &self.groups {
            // Group delimiter tag
            let tag_byte = match group.tag {
                AttributeGroupTag::OperationAttributes => 0x01,
                AttributeGroupTag::JobAttributes => 0x02,
                AttributeGroupTag::PrinterAttributes => 0x04,
                AttributeGroupTag::UnsupportedAttributes => 0x05,
                AttributeGroupTag::EndOfAttributes => 0x03,
            };
            buf.put_u8(tag_byte);

            for attr in &group.attributes {
                // Value tag
                let vt_byte = match attr.value_tag {
                    ValueTag::Integer => 0x21,
                    ValueTag::Boolean => 0x22,
                    ValueTag::Enum => 0x23,
                    ValueTag::DateTime => 0x31,
                    ValueTag::TextWithoutLanguage => 0x41,
                    ValueTag::NameWithoutLanguage => 0x42,
                    ValueTag::Keyword => 0x44,
                    ValueTag::Uri => 0x45,
                    ValueTag::Charset => 0x47,
                    ValueTag::NaturalLanguage => 0x48,
                    ValueTag::MimeMediaType => 0x49,
                };
                buf.put_u8(vt_byte);

                // Name length + name
                #[allow(clippy::cast_possible_truncation)]
                let name_len = attr.name.len() as u16;
                buf.put_u16(name_len);
                buf.put_slice(attr.name.as_bytes());

                // Value length + value
                #[allow(clippy::cast_possible_truncation)]
                let value_len = attr.value.len() as u16;
                buf.put_u16(value_len);
                buf.put_slice(&attr.value);
            }
        }

        // End-of-attributes tag
        buf.put_u8(0x03);

        buf.to_vec()
    }

    /// Build a minimal required operation-attributes group containing
    /// `attributes-charset` and `attributes-natural-language`.
    #[must_use]
    pub fn standard_operation_attributes() -> ResponseAttributeGroup {
        ResponseAttributeGroup {
            tag: AttributeGroupTag::OperationAttributes,
            attributes: vec![
                ResponseAttribute::charset("attributes-charset", "utf-8"),
                ResponseAttribute::natural_language("attributes-natural-language", "en"),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_response_header() {
        let resp = IppResponseBuilder::new(IppStatusCode::SuccessfulOk, 42)
            .add_group(IppResponseBuilder::standard_operation_attributes())
            .build();

        // Version 2.0
        assert_eq!(resp[0], 0x02);
        assert_eq!(resp[1], 0x00);
        // Status 0x0000
        assert_eq!(resp[2], 0x00);
        assert_eq!(resp[3], 0x00);
        // Request ID 42
        assert_eq!(u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]), 42);
    }

    #[test]
    fn roundtrip_response_has_correct_structure() {
        let resp_bytes = IppResponseBuilder::new(IppStatusCode::SuccessfulOk, 1)
            .add_group(IppResponseBuilder::standard_operation_attributes())
            .build();

        // Verify header: version (2.0), status (0x0000), request-id (1)
        assert_eq!(resp_bytes[0], 0x02);
        assert_eq!(resp_bytes[1], 0x00);
        assert_eq!(u16::from_be_bytes([resp_bytes[2], resp_bytes[3]]), 0x0000);
        assert_eq!(
            u32::from_be_bytes([resp_bytes[4], resp_bytes[5], resp_bytes[6], resp_bytes[7]]),
            1
        );
        // First group tag should be operation-attributes (0x01)
        assert_eq!(resp_bytes[8], 0x01);
        // Should end with end-of-attributes tag (0x03)
        assert_eq!(*resp_bytes.last().unwrap(), 0x03);
    }

    #[test]
    fn status_code_success_predicate() {
        assert!(IppStatusCode::SuccessfulOk.is_success());
        assert!(IppStatusCode::SuccessfulOkIgnoredOrSubstitutedAttributes.is_success());
        assert!(!IppStatusCode::ClientErrorBadRequest.is_success());
        assert!(!IppStatusCode::ServerErrorInternalError.is_success());
    }
}
