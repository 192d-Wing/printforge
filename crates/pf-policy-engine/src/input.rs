// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Policy evaluation input types.
//!
//! The [`PolicyInput`] struct aggregates all context needed by `OPA` / `Rego`
//! rules: user identity, job metadata, printer capabilities, and current
//! quota consumption.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement

use serde::{Deserialize, Serialize};

use pf_common::fleet::PrinterId;
use pf_common::identity::{Edipi, Role};
use pf_common::job::{ColorMode, CostCenter, MediaSize, Sides};
use pf_common::policy::QuotaStatus;

use crate::error::PolicyError;

/// Capabilities that the target printer advertises.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrinterCapabilities {
    /// Whether the printer supports color output.
    pub color_supported: bool,
    /// Whether the printer supports duplex printing.
    pub duplex_supported: bool,
    /// Supported media sizes.
    pub supported_media: Vec<MediaSize>,
}

/// Everything the policy engine needs to make a decision about a print job.
///
/// This struct is serialized to JSON and sent to `OPA` as the `input` document.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    /// The authenticated user's EDIPI.
    pub user_edipi: Edipi,
    /// The roles assigned to the user.
    pub user_roles: Vec<Role>,
    /// The organizational cost center for chargeback.
    pub cost_center: CostCenter,
    /// Target printer identifier.
    pub printer_id: PrinterId,
    /// Printer capabilities (color, duplex, media).
    pub printer_capabilities: PrinterCapabilities,
    /// Number of pages in the submitted document.
    pub page_count: u32,
    /// Requested number of copies.
    pub copies: u16,
    /// Requested duplex/simplex mode.
    pub sides: Sides,
    /// Requested color mode.
    pub color: ColorMode,
    /// Requested media size.
    pub media: MediaSize,
    /// The user's current quota consumption for the billing period.
    pub quota_status: QuotaStatus,
}

impl PolicyInput {
    /// Validate the input before sending to the policy engine.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InputValidation`] if the page count is zero.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.page_count == 0 {
            return Err(PolicyError::InputValidation(
                "page_count must be greater than zero".to_string(),
            ));
        }
        if self.copies == 0 {
            return Err(PolicyError::InputValidation(
                "copies must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    /// Total number of physical pages this job will produce,
    /// accounting for copies.
    #[must_use]
    pub fn total_pages(&self) -> u32 {
        self.page_count.saturating_mul(u32::from(self.copies))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::fleet::PrinterId;
    use pf_common::identity::Edipi;
    use pf_common::job::CostCenter;

    fn sample_input(page_count: u32, copies: u16) -> PolicyInput {
        PolicyInput {
            user_edipi: Edipi::new("1234567890").unwrap(),
            user_roles: vec![Role::User],
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            printer_capabilities: PrinterCapabilities {
                color_supported: true,
                duplex_supported: true,
                supported_media: vec![MediaSize::Letter, MediaSize::Legal],
            },
            page_count,
            copies,
            sides: Sides::TwoSidedLongEdge,
            color: ColorMode::Grayscale,
            media: MediaSize::Letter,
            quota_status: QuotaStatus {
                limit: 500,
                used: 100,
                color_limit: 50,
                color_used: 10,
            },
        }
    }

    #[test]
    fn validate_rejects_zero_page_count() {
        let input = sample_input(0, 1);
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_copies() {
        let input = sample_input(10, 0);
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_input() {
        let input = sample_input(10, 2);
        assert!(input.validate().is_ok());
    }

    #[test]
    fn total_pages_accounts_for_copies() {
        let input = sample_input(10, 3);
        assert_eq!(input.total_pages(), 30);
    }

    #[test]
    fn total_pages_saturates_on_overflow() {
        let input = sample_input(u32::MAX, 2);
        assert_eq!(input.total_pages(), u32::MAX);
    }

    #[test]
    fn policy_input_serializes_to_json() {
        let input = sample_input(10, 1);
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("PRN-0042"));
    }
}
