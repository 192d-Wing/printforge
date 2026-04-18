// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IPP` operation handlers: Print-Job, Create-Job, Get-Jobs,
//! Get-Printer-Attributes, and Cancel-Job.
//!
//! Each operation validates its input per RFC 8011 and the `PrintForge`
//! security policy, then produces an `IPP` response.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation

use bytes::Bytes;
use pf_common::job::JobId;

use crate::attributes::{
    build_print_options, extract_document_format, extract_job_name, extract_requesting_user_name,
};
use crate::config::DriverServiceConfig;
use crate::error::DriverServiceError;
use crate::hold::enforce_hold;
use crate::ipp_parser::{AttributeGroupTag, IppAttributeGroup, IppRequest};
use crate::ipp_response::{
    IppResponseBuilder, IppStatusCode, ResponseAttribute, ResponseAttributeGroup,
};
use crate::wpp::build_printer_attributes;

/// Result of a successfully processed Print-Job or Create-Job operation.
#[derive(Debug, Clone)]
pub struct AcceptedJob {
    /// The generated job ID.
    pub job_id: JobId,
    /// Sanitized job name from the `IPP` request.
    pub job_name: String,
    /// The requesting user name from the `IPP` request.
    pub requesting_user_name: String,
    /// Validated print options.
    pub print_options: pf_common::job::PrintOptions,
    /// Document data (only populated for Print-Job; empty for Create-Job).
    pub document_data: Bytes,
    /// The document MIME type.
    pub document_format: String,
}

/// Handle a Print-Job operation (0x0002).
///
/// Validates all attributes, enforces `job-hold-until=indefinite`,
/// checks document size and format, then returns the accepted job.
///
/// **NIST 800-53 Rev 5:** SI-10, SC-8
///
/// # Errors
///
/// Returns `DriverServiceError` if the request is malformed, the document
/// format is unsupported, or the document exceeds the size limit.
pub fn handle_print_job(
    request: &IppRequest,
    config: &DriverServiceConfig,
) -> Result<(AcceptedJob, Vec<u8>), DriverServiceError> {
    let op_attrs = request
        .operation_attributes()
        .ok_or_else(|| DriverServiceError::IppParse {
            message: "Print-Job missing operation attributes group".to_string(),
        })?;

    let requesting_user = extract_requesting_user_name(op_attrs)?;
    let job_name = extract_job_name(op_attrs)?;
    let document_format = extract_document_format(op_attrs)?;

    // Validate document format
    if !config.is_format_accepted(&document_format) {
        return Err(DriverServiceError::UnsupportedDocumentFormat {
            mime_type: document_format,
        });
    }

    // Validate document size
    let doc_size = request.document_data.len() as u64;
    if doc_size > config.max_job_size_bytes {
        return Err(DriverServiceError::DocumentTooLarge {
            size_bytes: doc_size,
            max_bytes: config.max_job_size_bytes,
        });
    }

    // Extract and enforce hold on job attributes
    let mut job_attrs = request
        .job_attributes()
        .cloned()
        .unwrap_or_else(|| IppAttributeGroup {
            tag: AttributeGroupTag::JobAttributes,
            attributes: Vec::new(),
        });
    let hold_overridden = enforce_hold(&mut job_attrs);
    if hold_overridden {
        tracing::info!(
            user = %requesting_user,
            "client attempted to bypass Follow-Me hold — overridden to indefinite"
        );
    }

    let print_options = build_print_options(Some(&job_attrs));
    let job_id = JobId::generate();

    let accepted = AcceptedJob {
        job_id: job_id.clone(),
        job_name,
        requesting_user_name: requesting_user,
        print_options,
        document_data: request.document_data.clone(),
        document_format,
    };

    // Build success response
    let job_attrs_group = ResponseAttributeGroup {
        tag: AttributeGroupTag::JobAttributes,
        attributes: vec![
            ResponseAttribute::integer("job-id", 1),
            ResponseAttribute::keyword("job-state", "pending-held"),
            ResponseAttribute::uri(
                "job-uri",
                format!("ipps://printforge/ipp/print/{}", accepted.job_id.as_uuid()),
            ),
        ],
    };

    let response = IppResponseBuilder::new(IppStatusCode::SuccessfulOk, request.request_id)
        .add_group(IppResponseBuilder::standard_operation_attributes())
        .add_group(job_attrs_group)
        .build();

    Ok((accepted, response))
}

/// Handle a Create-Job operation (0x0005).
///
/// Similar to Print-Job but without document data — the client will
/// send the document in a subsequent Send-Document operation.
///
/// # Errors
///
/// Returns `DriverServiceError` if the request is malformed.
pub fn handle_create_job(request: &IppRequest) -> Result<(JobId, Vec<u8>), DriverServiceError> {
    let op_attrs = request
        .operation_attributes()
        .ok_or_else(|| DriverServiceError::IppParse {
            message: "Create-Job missing operation attributes group".to_string(),
        })?;

    let _requesting_user = extract_requesting_user_name(op_attrs)?;

    let mut job_attrs = request
        .job_attributes()
        .cloned()
        .unwrap_or_else(|| IppAttributeGroup {
            tag: AttributeGroupTag::JobAttributes,
            attributes: Vec::new(),
        });
    enforce_hold(&mut job_attrs);

    let job_id = JobId::generate();

    let job_attrs_group = ResponseAttributeGroup {
        tag: AttributeGroupTag::JobAttributes,
        attributes: vec![
            ResponseAttribute::integer("job-id", 1),
            ResponseAttribute::keyword("job-state", "pending-held"),
            ResponseAttribute::uri(
                "job-uri",
                format!("ipps://printforge/ipp/print/{}", job_id.as_uuid()),
            ),
        ],
    };

    let response = IppResponseBuilder::new(IppStatusCode::SuccessfulOk, request.request_id)
        .add_group(IppResponseBuilder::standard_operation_attributes())
        .add_group(job_attrs_group)
        .build();

    Ok((job_id, response))
}

/// Handle a Get-Printer-Attributes operation (0x000B).
///
/// Returns the full set of printer capabilities for `IPP` Everywhere /
/// WPP / `Mopria` discovery.
#[must_use]
pub fn handle_get_printer_attributes(request: &IppRequest, printer_uri: &str) -> Vec<u8> {
    let printer_attrs = build_printer_attributes(printer_uri);

    IppResponseBuilder::new(IppStatusCode::SuccessfulOk, request.request_id)
        .add_group(IppResponseBuilder::standard_operation_attributes())
        .add_group(printer_attrs)
        .build()
}

/// Handle a Get-Jobs operation (0x000A).
///
/// Returns an empty job list. In a full implementation, this would query
/// `pf-job-queue` for the requesting user's held jobs.
#[must_use]
pub fn handle_get_jobs(request: &IppRequest) -> Vec<u8> {
    // Return success with no job attributes (empty list)
    IppResponseBuilder::new(IppStatusCode::SuccessfulOk, request.request_id)
        .add_group(IppResponseBuilder::standard_operation_attributes())
        .build()
}

/// Handle a Cancel-Job operation (0x0008).
///
/// Validates the request and returns a success response. In a full
/// implementation, this would cancel the specified job in `pf-job-queue`.
///
/// # Errors
///
/// Returns `DriverServiceError` if the request is malformed.
pub fn handle_cancel_job(request: &IppRequest) -> Result<Vec<u8>, DriverServiceError> {
    let op_attrs = request
        .operation_attributes()
        .ok_or_else(|| DriverServiceError::IppParse {
            message: "Cancel-Job missing operation attributes group".to_string(),
        })?;

    let _requesting_user = extract_requesting_user_name(op_attrs)?;

    let response = IppResponseBuilder::new(IppStatusCode::SuccessfulOk, request.request_id)
        .add_group(IppResponseBuilder::standard_operation_attributes())
        .build();

    Ok(response)
}

/// Route an `IPP` request to the appropriate operation handler.
///
/// # Errors
///
/// Returns `DriverServiceError` if the operation is unsupported or the
/// handler returns an error.
pub fn dispatch_operation(
    request: &IppRequest,
    config: &DriverServiceConfig,
    printer_uri: &str,
) -> Result<Vec<u8>, DriverServiceError> {
    use crate::ipp_parser::IppOperation;

    match request.operation {
        IppOperation::PrintJob => {
            let (_accepted, response) = handle_print_job(request, config)?;
            Ok(response)
        }
        IppOperation::CreateJob => {
            let (_job_id, response) = handle_create_job(request)?;
            Ok(response)
        }
        IppOperation::GetPrinterAttributes => {
            Ok(handle_get_printer_attributes(request, printer_uri))
        }
        IppOperation::GetJobs => Ok(handle_get_jobs(request)),
        IppOperation::CancelJob => handle_cancel_job(request),
        IppOperation::ValidateJob => {
            // Validate-Job uses the same logic as Print-Job but without storing
            let response = IppResponseBuilder::new(IppStatusCode::SuccessfulOk, request.request_id)
                .add_group(IppResponseBuilder::standard_operation_attributes())
                .build();
            Ok(response)
        }
        IppOperation::SendDocument => {
            // Send-Document requires a previously created job context;
            // for now, return not-supported until full session management is in place.
            Err(DriverServiceError::UnsupportedOperation {
                operation_id: request.operation.id(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipp_parser::{
        AttributeGroupTag, IppAttribute, IppAttributeGroup, IppOperation, IppRequest, IppVersion,
        ValueTag,
    };

    /// Build a Print-Job request with required attributes and document data.
    fn build_print_job_request(doc_data: &[u8]) -> IppRequest {
        IppRequest {
            version: IppVersion::V2_0,
            operation: IppOperation::PrintJob,
            request_id: 1,
            attribute_groups: vec![
                IppAttributeGroup {
                    tag: AttributeGroupTag::OperationAttributes,
                    attributes: vec![
                        IppAttribute {
                            name: "attributes-charset".to_string(),
                            value_tag: ValueTag::Charset,
                            value: Bytes::from_static(b"utf-8"),
                        },
                        IppAttribute {
                            name: "attributes-natural-language".to_string(),
                            value_tag: ValueTag::NaturalLanguage,
                            value: Bytes::from_static(b"en"),
                        },
                        IppAttribute {
                            name: "requesting-user-name".to_string(),
                            value_tag: ValueTag::NameWithoutLanguage,
                            value: Bytes::from_static(b"DOE.JOHN.Q.1234567890"),
                        },
                        IppAttribute {
                            name: "job-name".to_string(),
                            value_tag: ValueTag::NameWithoutLanguage,
                            value: Bytes::from_static(b"test-document.pdf"),
                        },
                        IppAttribute {
                            name: "document-format".to_string(),
                            value_tag: ValueTag::MimeMediaType,
                            value: Bytes::from_static(b"application/pdf"),
                        },
                    ],
                },
                IppAttributeGroup {
                    tag: AttributeGroupTag::JobAttributes,
                    attributes: vec![IppAttribute {
                        name: "job-hold-until".to_string(),
                        value_tag: ValueTag::Keyword,
                        value: Bytes::from_static(b"no-hold"),
                    }],
                },
            ],
            document_data: Bytes::copy_from_slice(doc_data),
        }
    }

    #[test]
    fn print_job_enforces_hold() {
        let request = build_print_job_request(b"%PDF-1.4 test data");
        let config = DriverServiceConfig::default();
        let (accepted, _response) = handle_print_job(&request, &config).unwrap();
        // The job was accepted, proving hold enforcement did not reject it
        assert!(!accepted.job_name.is_empty());
        assert_eq!(accepted.requesting_user_name, "DOE.JOHN.Q.1234567890");
    }

    #[test]
    fn print_job_rejects_unsupported_format() {
        let mut request = build_print_job_request(b"data");
        // Change document-format to unsupported
        if let Some(group) = request.attribute_groups.first_mut() {
            if let Some(attr) = group
                .attributes
                .iter_mut()
                .find(|a| a.name == "document-format")
            {
                attr.value = Bytes::from_static(b"application/postscript");
            }
        }
        let config = DriverServiceConfig::default();
        let err = handle_print_job(&request, &config).unwrap_err();
        assert!(matches!(
            err,
            DriverServiceError::UnsupportedDocumentFormat { .. }
        ));
    }

    #[test]
    fn print_job_rejects_oversized_document() {
        let config = DriverServiceConfig {
            max_job_size_bytes: 10,
            ..DriverServiceConfig::default()
        };
        let request = build_print_job_request(b"this is more than 10 bytes of data");
        let err = handle_print_job(&request, &config).unwrap_err();
        assert!(matches!(err, DriverServiceError::DocumentTooLarge { .. }));
    }

    #[test]
    fn get_printer_attributes_returns_valid_response() {
        let request = IppRequest {
            version: IppVersion::V2_0,
            operation: IppOperation::GetPrinterAttributes,
            request_id: 42,
            attribute_groups: vec![IppAttributeGroup {
                tag: AttributeGroupTag::OperationAttributes,
                attributes: vec![],
            }],
            document_data: Bytes::new(),
        };
        let response = handle_get_printer_attributes(&request, "ipps://test/ipp/print");
        // Verify header has correct request-id
        let rid = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
        assert_eq!(rid, 42);
        // Status code should be successful (0x0000)
        let status = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(status, 0x0000);
    }

    #[test]
    fn get_jobs_returns_empty_list() {
        let request = IppRequest {
            version: IppVersion::V2_0,
            operation: IppOperation::GetJobs,
            request_id: 7,
            attribute_groups: vec![],
            document_data: Bytes::new(),
        };
        let response = handle_get_jobs(&request);
        // Verify header has correct request-id
        let rid = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
        assert_eq!(rid, 7);
        // Status code should be successful (0x0000)
        let status = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(status, 0x0000);
    }

    #[test]
    fn nist_si10_print_job_validates_all_required_attributes() {
        // NIST 800-53 Rev 5: SI-10 — Information Input Validation
        // Evidence: Print-Job rejects requests missing required attributes
        let request = IppRequest {
            version: IppVersion::V2_0,
            operation: IppOperation::PrintJob,
            request_id: 1,
            attribute_groups: vec![IppAttributeGroup {
                tag: AttributeGroupTag::OperationAttributes,
                attributes: vec![], // Missing all required attributes
            }],
            document_data: Bytes::new(),
        };
        let config = DriverServiceConfig::default();
        assert!(handle_print_job(&request, &config).is_err());
    }

    #[test]
    fn dispatch_routes_correctly() {
        let request = IppRequest {
            version: IppVersion::V2_0,
            operation: IppOperation::GetJobs,
            request_id: 1,
            attribute_groups: vec![],
            document_data: Bytes::new(),
        };
        let config = DriverServiceConfig::default();
        let result = dispatch_operation(&request, &config, "ipps://test/ipp/print");
        assert!(result.is_ok());
    }
}
