// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fleet Admin approval gate for firmware deployment.
//!
//! **NIST 800-53 Rev 5:** CM-3 — Configuration Change Control
//! Firmware MUST NOT be deployed without explicit `FleetAdmin` approval,
//! even in automated pipelines.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterModel;
use pf_common::identity::Edipi;

use crate::error::FirmwareError;
use crate::validation::ValidatedFirmware;

/// Status of a firmware approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// Awaiting `FleetAdmin` review.
    Pending,
    /// Approved for deployment.
    Approved,
    /// Rejected by `FleetAdmin`.
    Rejected,
    /// Approval expired (exceeded review window).
    Expired,
}

/// A firmware deployment approval request submitted to a `FleetAdmin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique approval request identifier.
    pub id: Uuid,

    /// The validated firmware this request is for.
    pub firmware: ValidatedFirmware,

    /// Target printer model.
    pub model: PrinterModel,

    /// Firmware version string.
    pub version: String,

    /// Current status of the request.
    pub status: ApprovalStatus,

    /// Who submitted the approval request.
    pub requested_by: Edipi,

    /// When the request was created.
    pub requested_at: DateTime<Utc>,

    /// The `FleetAdmin` who reviewed the request (if reviewed).
    pub reviewed_by: Option<Edipi>,

    /// When the request was reviewed.
    pub reviewed_at: Option<DateTime<Utc>>,

    /// Reviewer comments or justification.
    pub review_notes: Option<String>,
}

impl ApprovalRequest {
    /// Create a new pending approval request.
    #[must_use]
    pub fn new(
        firmware: ValidatedFirmware,
        model: PrinterModel,
        version: String,
        requested_by: Edipi,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            firmware,
            model,
            version,
            status: ApprovalStatus::Pending,
            requested_by,
            requested_at: Utc::now(),
            reviewed_by: None,
            reviewed_at: None,
            review_notes: None,
        }
    }

    /// Approve the firmware for deployment.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Config`] if the request is not in [`ApprovalStatus::Pending`].
    pub fn approve(&mut self, reviewer: Edipi, notes: Option<String>) -> Result<(), FirmwareError> {
        if self.status != ApprovalStatus::Pending {
            return Err(FirmwareError::Config {
                message: format!(
                    "cannot approve request {}: status is {:?}",
                    self.id, self.status
                ),
            });
        }

        self.status = ApprovalStatus::Approved;
        self.reviewed_by = Some(reviewer);
        self.reviewed_at = Some(Utc::now());
        self.review_notes = notes;

        tracing::info!(
            approval_id = %self.id,
            firmware_id = %self.firmware.firmware_id,
            "firmware approved for deployment"
        );

        Ok(())
    }

    /// Reject the firmware deployment.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Config`] if the request is not in [`ApprovalStatus::Pending`].
    pub fn reject(&mut self, reviewer: Edipi, notes: String) -> Result<(), FirmwareError> {
        if self.status != ApprovalStatus::Pending {
            return Err(FirmwareError::Config {
                message: format!(
                    "cannot reject request {}: status is {:?}",
                    self.id, self.status
                ),
            });
        }

        self.status = ApprovalStatus::Rejected;
        self.reviewed_by = Some(reviewer);
        self.reviewed_at = Some(Utc::now());
        self.review_notes = Some(notes);

        tracing::info!(
            approval_id = %self.id,
            firmware_id = %self.firmware.firmware_id,
            "firmware deployment rejected"
        );

        Ok(())
    }

    /// Check whether this firmware has been approved and can be deployed.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.status == ApprovalStatus::Approved
    }
}

/// Verify that a firmware has been approved before allowing deployment.
///
/// **NIST 800-53 Rev 5:** CM-3 — Configuration Change Control
/// This gate MUST be called before any deployment operation.
///
/// # Errors
///
/// Returns [`FirmwareError::NotApproved`] if the firmware has not been approved.
pub fn require_approval(
    firmware_id: Uuid,
    approval: &ApprovalRequest,
) -> Result<(), FirmwareError> {
    if !approval.is_approved() {
        return Err(FirmwareError::NotApproved { firmware_id });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validated_firmware() -> ValidatedFirmware {
        ValidatedFirmware {
            firmware_id: Uuid::new_v4(),
            computed_sha256: "abcdef1234567890".to_string(),
            signature_verified: true,
            validated_at: Utc::now(),
        }
    }

    fn make_test_edipi() -> Edipi {
        Edipi::new("1234567890").unwrap()
    }

    #[test]
    fn nist_cm3_approval_starts_pending() {
        // NIST 800-53 Rev 5: CM-3 — New requests start as pending
        let fw = make_validated_firmware();
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        let req = ApprovalRequest::new(fw, model, "4.11.2.1".to_string(), make_test_edipi());
        assert_eq!(req.status, ApprovalStatus::Pending);
        assert!(!req.is_approved());
    }

    #[test]
    fn nist_cm3_approve_sets_status_and_reviewer() {
        // NIST 800-53 Rev 5: CM-3 — Approval records reviewer identity
        let fw = make_validated_firmware();
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        let mut req = ApprovalRequest::new(fw, model, "4.11.2.1".to_string(), make_test_edipi());
        let reviewer = Edipi::new("9876543210").unwrap();
        req.approve(reviewer, Some("STIG review passed".to_string()))
            .unwrap();
        assert!(req.is_approved());
        assert!(req.reviewed_by.is_some());
        assert!(req.reviewed_at.is_some());
    }

    #[test]
    fn nist_cm3_reject_sets_status() {
        let fw = make_validated_firmware();
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        let mut req = ApprovalRequest::new(fw, model, "4.11.2.1".to_string(), make_test_edipi());
        let reviewer = Edipi::new("9876543210").unwrap();
        req.reject(reviewer, "STIG delta unacceptable".to_string())
            .unwrap();
        assert_eq!(req.status, ApprovalStatus::Rejected);
        assert!(!req.is_approved());
    }

    #[test]
    fn nist_cm3_cannot_approve_twice() {
        let fw = make_validated_firmware();
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        let mut req = ApprovalRequest::new(fw, model, "4.11.2.1".to_string(), make_test_edipi());
        let reviewer = Edipi::new("9876543210").unwrap();
        req.approve(reviewer.clone(), None).unwrap();
        let result = req.approve(reviewer, None);
        assert!(result.is_err());
    }

    #[test]
    fn nist_cm3_require_approval_rejects_unapproved() {
        // NIST 800-53 Rev 5: CM-3 — Deployment gate enforced
        let fw = make_validated_firmware();
        let firmware_id = fw.firmware_id;
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        let req = ApprovalRequest::new(fw, model, "4.11.2.1".to_string(), make_test_edipi());
        let result = require_approval(firmware_id, &req);
        assert!(matches!(result, Err(FirmwareError::NotApproved { .. })));
    }

    #[test]
    fn nist_cm3_require_approval_passes_approved() {
        let fw = make_validated_firmware();
        let firmware_id = fw.firmware_id;
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        let mut req = ApprovalRequest::new(fw, model, "4.11.2.1".to_string(), make_test_edipi());
        let reviewer = Edipi::new("9876543210").unwrap();
        req.approve(reviewer, None).unwrap();
        assert!(require_approval(firmware_id, &req).is_ok());
    }
}
