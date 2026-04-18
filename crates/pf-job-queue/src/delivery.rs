// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! IPPS client types for delivering print jobs to physical printers.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
//! All delivery uses IPPS (IPP over TLS 1.2+). Plaintext IPP is never used.

use bytes::Bytes;
use pf_common::fleet::PrinterId;
use pf_common::job::{JobId, JobStatus, PrintOptions};
use serde::{Deserialize, Serialize};

use crate::error::JobQueueError;

/// A request to deliver a rendered job to a target printer via IPPS.
#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    /// The job being delivered.
    pub job_id: JobId,
    /// The target printer.
    pub printer_id: PrinterId,
    /// The IPPS URI of the target printer (e.g., `ipps://prn-0042.example.mil/ipp/print`).
    pub printer_uri: String,
    /// Print options to include in the IPPS request.
    pub options: PrintOptions,
    /// The rendered document payload.
    pub payload: Bytes,
}

/// The outcome of a delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    /// The job that was delivered.
    pub job_id: JobId,
    /// The printer that received the job.
    pub printer_id: PrinterId,
    /// Whether delivery succeeded.
    pub status: DeliveryStatus,
    /// The IPP status code returned by the printer, if any.
    pub ipp_status_code: Option<u16>,
}

/// Status of a delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Job accepted by the printer.
    Accepted,
    /// Printer rejected the job (e.g., unsupported format).
    Rejected,
    /// Network or TLS error prevented delivery.
    TransportError,
}

/// Trait for an IPPS delivery backend.
///
/// Implementations send the rendered document to a printer via IPPS
/// and return the outcome.
///
/// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
pub trait DeliveryBackend: Send + Sync {
    /// Send a job to a printer.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Delivery` on transport or protocol errors.
    fn deliver(
        &self,
        request: &DeliveryRequest,
    ) -> impl std::future::Future<Output = Result<DeliveryResult, JobQueueError>> + Send;
}

/// Map a `DeliveryResult` to the appropriate `JobStatus` for the lifecycle
/// state machine.
#[must_use]
pub fn delivery_result_to_status(result: &DeliveryResult) -> JobStatus {
    match result.status {
        DeliveryStatus::Accepted => JobStatus::Printing,
        DeliveryStatus::Rejected | DeliveryStatus::TransportError => JobStatus::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_accepted_maps_to_printing() {
        let result = DeliveryResult {
            job_id: JobId::generate(),
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            status: DeliveryStatus::Accepted,
            ipp_status_code: Some(0),
        };
        assert_eq!(delivery_result_to_status(&result), JobStatus::Printing);
    }

    #[test]
    fn delivery_rejected_maps_to_failed() {
        let result = DeliveryResult {
            job_id: JobId::generate(),
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            status: DeliveryStatus::Rejected,
            ipp_status_code: Some(0x0400),
        };
        assert_eq!(delivery_result_to_status(&result), JobStatus::Failed);
    }

    #[test]
    fn delivery_transport_error_maps_to_failed() {
        let result = DeliveryResult {
            job_id: JobId::generate(),
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            status: DeliveryStatus::TransportError,
            ipp_status_code: None,
        };
        assert_eq!(delivery_result_to_status(&result), JobStatus::Failed);
    }
}
