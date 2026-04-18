// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IPP` 2.0 message parser types.
//!
//! Provides structures for parsing `IPP` request messages into strongly-typed
//! operations, attribute groups, and individual attributes. All parsing
//! validates input lengths and value types per RFC 8011.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation

use bytes::Bytes;

use crate::error::DriverServiceError;

/// `IPP` protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IppVersion {
    /// Major version number.
    pub major: u8,
    /// Minor version number.
    pub minor: u8,
}

impl IppVersion {
    /// `IPP` 2.0 — the version this service targets.
    pub const V2_0: Self = Self { major: 2, minor: 0 };

    /// `IPP` 1.1 — minimum supported for legacy clients.
    pub const V1_1: Self = Self { major: 1, minor: 1 };
}

/// `IPP` operation identifiers (RFC 8011 section 5.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IppOperation {
    /// Print-Job (0x0002): single-request document submission.
    PrintJob,
    /// Validate-Job (0x0004): check if a job would be accepted.
    ValidateJob,
    /// Create-Job (0x0005): first phase of two-phase submission.
    CreateJob,
    /// Send-Document (0x0006): second phase — sends document data.
    SendDocument,
    /// Get-Printer-Attributes (0x000B): capability discovery.
    GetPrinterAttributes,
    /// Get-Jobs (0x000A): list jobs for the requesting user.
    GetJobs,
    /// Cancel-Job (0x0008): cancel a held job.
    CancelJob,
}

impl IppOperation {
    /// Parse a raw `u16` operation ID into a known `IppOperation`.
    ///
    /// # Errors
    ///
    /// Returns `DriverServiceError::UnsupportedOperation` if the ID is unknown.
    pub fn from_id(id: u16) -> Result<Self, DriverServiceError> {
        match id {
            0x0002 => Ok(Self::PrintJob),
            0x0004 => Ok(Self::ValidateJob),
            0x0005 => Ok(Self::CreateJob),
            0x0006 => Ok(Self::SendDocument),
            0x000B => Ok(Self::GetPrinterAttributes),
            0x000A => Ok(Self::GetJobs),
            0x0008 => Ok(Self::CancelJob),
            _ => Err(DriverServiceError::UnsupportedOperation { operation_id: id }),
        }
    }

    /// Return the `u16` operation ID for this operation.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Self::PrintJob => 0x0002,
            Self::ValidateJob => 0x0004,
            Self::CreateJob => 0x0005,
            Self::SendDocument => 0x0006,
            Self::GetPrinterAttributes => 0x000B,
            Self::GetJobs => 0x000A,
            Self::CancelJob => 0x0008,
        }
    }
}

/// Tag values for `IPP` attribute groups (RFC 8011 section 3.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributeGroupTag {
    /// Operation attributes (tag 0x01).
    OperationAttributes,
    /// Job attributes (tag 0x02).
    JobAttributes,
    /// Printer attributes (tag 0x04).
    PrinterAttributes,
    /// Unsupported attributes returned by the server (tag 0x05).
    UnsupportedAttributes,
    /// End-of-attributes marker (tag 0x03).
    EndOfAttributes,
}

impl AttributeGroupTag {
    /// Parse a raw tag byte.
    ///
    /// # Errors
    ///
    /// Returns `DriverServiceError::IppParse` if the tag is unrecognized.
    pub fn from_byte(tag: u8) -> Result<Self, DriverServiceError> {
        match tag {
            0x01 => Ok(Self::OperationAttributes),
            0x02 => Ok(Self::JobAttributes),
            0x04 => Ok(Self::PrinterAttributes),
            0x05 => Ok(Self::UnsupportedAttributes),
            0x03 => Ok(Self::EndOfAttributes),
            _ => Err(DriverServiceError::IppParse {
                message: format!("unknown attribute group tag: 0x{tag:02x}"),
            }),
        }
    }
}

/// Value-type tags for individual `IPP` attributes (RFC 8011 section 3.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueTag {
    /// Integer (tag 0x21).
    Integer,
    /// Boolean (tag 0x22).
    Boolean,
    /// Enum value (tag 0x23).
    Enum,
    /// Text without language (tag 0x41).
    TextWithoutLanguage,
    /// Name without language (tag 0x42).
    NameWithoutLanguage,
    /// Keyword (tag 0x44).
    Keyword,
    /// URI (tag 0x45).
    Uri,
    /// Charset (tag 0x47).
    Charset,
    /// Natural language (tag 0x48).
    NaturalLanguage,
    /// MIME media type (tag 0x49).
    MimeMediaType,
    /// `DateTime` (tag 0x31).
    DateTime,
}

impl ValueTag {
    /// Parse a raw value-type tag byte.
    ///
    /// # Errors
    ///
    /// Returns `DriverServiceError::IppParse` if the tag is unrecognized.
    pub fn from_byte(tag: u8) -> Result<Self, DriverServiceError> {
        match tag {
            0x21 => Ok(Self::Integer),
            0x22 => Ok(Self::Boolean),
            0x23 => Ok(Self::Enum),
            0x41 => Ok(Self::TextWithoutLanguage),
            0x42 => Ok(Self::NameWithoutLanguage),
            0x44 => Ok(Self::Keyword),
            0x45 => Ok(Self::Uri),
            0x47 => Ok(Self::Charset),
            0x48 => Ok(Self::NaturalLanguage),
            0x49 => Ok(Self::MimeMediaType),
            0x31 => Ok(Self::DateTime),
            _ => Err(DriverServiceError::IppParse {
                message: format!("unknown value tag: 0x{tag:02x}"),
            }),
        }
    }
}

/// A single `IPP` attribute: name, value tag, and raw value bytes.
#[derive(Debug, Clone)]
pub struct IppAttribute {
    /// Attribute name (e.g., `requesting-user-name`).
    pub name: String,
    /// The value-type tag.
    pub value_tag: ValueTag,
    /// Raw value bytes — interpretation depends on `value_tag`.
    pub value: Bytes,
}

/// A group of `IPP` attributes sharing the same group tag.
#[derive(Debug, Clone)]
pub struct IppAttributeGroup {
    /// The group tag identifying this attribute group.
    pub tag: AttributeGroupTag,
    /// Attributes within this group.
    pub attributes: Vec<IppAttribute>,
}

impl IppAttributeGroup {
    /// Find the first attribute with the given name.
    #[must_use]
    pub fn find_attribute(&self, name: &str) -> Option<&IppAttribute> {
        self.attributes.iter().find(|a| a.name == name)
    }
}

/// A parsed `IPP` request message.
#[derive(Debug, Clone)]
pub struct IppRequest {
    /// Protocol version from the request header.
    pub version: IppVersion,
    /// The requested operation.
    pub operation: IppOperation,
    /// Request ID for correlating request/response pairs.
    pub request_id: u32,
    /// Attribute groups in the order they appeared.
    pub attribute_groups: Vec<IppAttributeGroup>,
    /// Document data following the attributes (may be empty for non-document ops).
    pub document_data: Bytes,
}

impl IppRequest {
    /// Return the operation-attributes group, if present.
    #[must_use]
    pub fn operation_attributes(&self) -> Option<&IppAttributeGroup> {
        self.attribute_groups
            .iter()
            .find(|g| g.tag == AttributeGroupTag::OperationAttributes)
    }

    /// Return the job-attributes group, if present.
    #[must_use]
    pub fn job_attributes(&self) -> Option<&IppAttributeGroup> {
        self.attribute_groups
            .iter()
            .find(|g| g.tag == AttributeGroupTag::JobAttributes)
    }
}

/// Parse raw bytes into an `IppRequest`.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
///
/// # Errors
///
/// Returns `DriverServiceError::IppParse` if the message is malformed,
/// truncated, or contains invalid tags.
pub fn parse_ipp_request(data: &[u8]) -> Result<IppRequest, DriverServiceError> {
    // Minimum IPP header: version (2) + operation (2) + request-id (4) + end-tag (1) = 9
    if data.len() < 9 {
        return Err(DriverServiceError::IppParse {
            message: format!("message too short: {} bytes (minimum 9)", data.len()),
        });
    }

    let version = IppVersion {
        major: data[0],
        minor: data[1],
    };

    let operation_id = u16::from_be_bytes([data[2], data[3]]);
    let operation = IppOperation::from_id(operation_id)?;

    let request_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let mut offset = 8;
    let mut attribute_groups = Vec::new();

    while offset < data.len() {
        let tag_byte = data[offset];
        offset += 1;

        let group_tag = AttributeGroupTag::from_byte(tag_byte)?;

        if group_tag == AttributeGroupTag::EndOfAttributes {
            break;
        }

        let mut attributes = Vec::new();

        // Parse attributes within this group until we hit the next group tag or end
        while offset < data.len() {
            // Peek at the next byte — if it's a delimiter tag (0x00..=0x05), it's a new group
            if data[offset] <= 0x05 {
                break;
            }

            // Value tag
            let value_tag_byte = data[offset];
            offset += 1;

            let value_tag = ValueTag::from_byte(value_tag_byte)?;

            // Name length (2 bytes, big-endian)
            if offset + 2 > data.len() {
                return Err(DriverServiceError::IppParse {
                    message: "truncated attribute name length".to_string(),
                });
            }
            let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + name_len > data.len() {
                return Err(DriverServiceError::IppParse {
                    message: "truncated attribute name".to_string(),
                });
            }
            let name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
            offset += name_len;

            // Value length (2 bytes, big-endian)
            if offset + 2 > data.len() {
                return Err(DriverServiceError::IppParse {
                    message: "truncated attribute value length".to_string(),
                });
            }
            let value_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + value_len > data.len() {
                return Err(DriverServiceError::IppParse {
                    message: "truncated attribute value".to_string(),
                });
            }
            let value = Bytes::copy_from_slice(&data[offset..offset + value_len]);
            offset += value_len;

            attributes.push(IppAttribute {
                name,
                value_tag,
                value,
            });
        }

        attribute_groups.push(IppAttributeGroup {
            tag: group_tag,
            attributes,
        });
    }

    let document_data = if offset < data.len() {
        Bytes::copy_from_slice(&data[offset..])
    } else {
        Bytes::new()
    };

    Ok(IppRequest {
        version,
        operation,
        request_id,
        attribute_groups,
        document_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPP request for Print-Job with one operation attribute.
    fn build_minimal_print_job_request() -> Vec<u8> {
        let mut buf = Vec::new();
        // Version 2.0
        buf.extend_from_slice(&[0x02, 0x00]);
        // Operation: Print-Job (0x0002)
        buf.extend_from_slice(&[0x00, 0x02]);
        // Request ID: 1
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Operation attributes group tag (0x01)
        buf.push(0x01);
        // Charset attribute: value-tag=0x47, name="attributes-charset", value="utf-8"
        buf.push(0x47); // charset tag
        let name = b"attributes-charset";
        buf.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(name);
        let value = b"utf-8";
        buf.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(value);
        // End of attributes
        buf.push(0x03);
        // Document data
        buf.extend_from_slice(b"%PDF-fake-data");
        buf
    }

    #[test]
    fn parses_minimal_print_job() {
        let data = build_minimal_print_job_request();
        let req = parse_ipp_request(&data).unwrap();
        assert_eq!(req.version, IppVersion::V2_0);
        assert_eq!(req.operation, IppOperation::PrintJob);
        assert_eq!(req.request_id, 1);
        assert_eq!(req.attribute_groups.len(), 1);
        assert_eq!(req.document_data.as_ref(), b"%PDF-fake-data");
    }

    #[test]
    fn nist_si10_rejects_truncated_message() {
        let data = [0x02, 0x00, 0x00]; // too short
        assert!(parse_ipp_request(&data).is_err());
    }

    #[test]
    fn nist_si10_rejects_unknown_operation() {
        let mut data = build_minimal_print_job_request();
        // Replace operation with unknown 0xFFFF
        data[2] = 0xFF;
        data[3] = 0xFF;
        let err = parse_ipp_request(&data).unwrap_err();
        assert!(matches!(
            err,
            DriverServiceError::UnsupportedOperation {
                operation_id: 0xFFFF
            }
        ));
    }

    #[test]
    fn operation_roundtrip() {
        for op in [
            IppOperation::PrintJob,
            IppOperation::ValidateJob,
            IppOperation::CreateJob,
            IppOperation::SendDocument,
            IppOperation::GetPrinterAttributes,
            IppOperation::GetJobs,
            IppOperation::CancelJob,
        ] {
            assert_eq!(IppOperation::from_id(op.id()).unwrap(), op);
        }
    }

    #[test]
    fn attribute_group_find() {
        let group = IppAttributeGroup {
            tag: AttributeGroupTag::OperationAttributes,
            attributes: vec![IppAttribute {
                name: "requesting-user-name".to_string(),
                value_tag: ValueTag::NameWithoutLanguage,
                value: Bytes::from_static(b"testuser"),
            }],
        };
        assert!(group.find_attribute("requesting-user-name").is_some());
        assert!(group.find_attribute("nonexistent").is_none());
    }
}
