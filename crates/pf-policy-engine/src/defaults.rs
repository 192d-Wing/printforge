// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default print-settings enforcement.
//!
//! Organizations can mandate specific print defaults (e.g., duplex, grayscale,
//! draft quality) to reduce costs and environmental impact. This module checks
//! whether a job's requested settings deviate from the organizational defaults
//! and either modifies the job or denies it.
//!
//! **NIST 800-53 Rev 5:** CM-7 — Least Functionality

use pf_common::job::{ColorMode, Sides};
use pf_common::policy::PolicyDecision;

use crate::input::PolicyInput;

/// Organizational overrides for default print settings.
///
/// When an override is enabled, jobs that deviate from the default are
/// allowed but modified (e.g., forced to duplex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultOverrides {
    /// Force all jobs to duplex (two-sided) printing.
    pub force_duplex: bool,
    /// Force all jobs to grayscale (no color).
    pub force_grayscale: bool,
}

use serde::{Deserialize, Serialize};

impl Default for DefaultOverrides {
    fn default() -> Self {
        Self {
            force_duplex: true,
            force_grayscale: false,
        }
    }
}

/// Check the job's print settings against organizational defaults and
/// return a decision indicating whether modifications are needed.
///
/// Returns [`PolicyDecision::Allow`] if no modifications are needed,
/// or [`PolicyDecision::AllowWithModification`] describing the changes.
///
/// **NIST 800-53 Rev 5:** CM-7 — Least Functionality
#[must_use]
pub fn apply_defaults(input: &PolicyInput, overrides: &DefaultOverrides) -> PolicyDecision {
    let mut modifications = Vec::new();

    // Check duplex enforcement.
    // If the printer doesn't support duplex, allow as-is rather than
    // denying — the user can't comply with a hardware limitation.
    if overrides.force_duplex
        && input.sides == Sides::OneSided
        && input.printer_capabilities.duplex_supported
    {
        modifications.push("forced duplex (two-sided long-edge)");
    }

    // Check grayscale enforcement
    if overrides.force_grayscale && input.color != ColorMode::Grayscale {
        modifications.push("forced grayscale");
    }

    if modifications.is_empty() {
        PolicyDecision::Allow
    } else {
        PolicyDecision::AllowWithModification {
            reason: modifications.join("; "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::fleet::PrinterId;
    use pf_common::identity::{Edipi, Role};
    use pf_common::job::{ColorMode, CostCenter, MediaSize, Sides};
    use pf_common::policy::QuotaStatus;

    use crate::input::{PolicyInput, PrinterCapabilities};

    fn make_input(sides: Sides, color: ColorMode, duplex_supported: bool) -> PolicyInput {
        PolicyInput {
            user_edipi: Edipi::new("1234567890").unwrap(),
            user_roles: vec![Role::User],
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            printer_capabilities: PrinterCapabilities {
                color_supported: true,
                duplex_supported,
                supported_media: vec![MediaSize::Letter],
            },
            page_count: 10,
            copies: 1,
            sides,
            color,
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
    fn no_overrides_allows_any_settings() {
        let overrides = DefaultOverrides {
            force_duplex: false,
            force_grayscale: false,
        };
        let input = make_input(Sides::OneSided, ColorMode::Color, true);
        assert_eq!(apply_defaults(&input, &overrides), PolicyDecision::Allow);
    }

    #[test]
    fn force_duplex_modifies_one_sided_job() {
        let overrides = DefaultOverrides {
            force_duplex: true,
            force_grayscale: false,
        };
        let input = make_input(Sides::OneSided, ColorMode::Grayscale, true);
        let decision = apply_defaults(&input, &overrides);
        assert!(matches!(
            decision,
            PolicyDecision::AllowWithModification { .. }
        ));
    }

    #[test]
    fn force_duplex_allows_already_duplex_job() {
        let overrides = DefaultOverrides {
            force_duplex: true,
            force_grayscale: false,
        };
        let input = make_input(Sides::TwoSidedLongEdge, ColorMode::Grayscale, true);
        assert_eq!(apply_defaults(&input, &overrides), PolicyDecision::Allow);
    }

    #[test]
    fn force_duplex_skips_if_printer_lacks_duplex() {
        let overrides = DefaultOverrides {
            force_duplex: true,
            force_grayscale: false,
        };
        let input = make_input(Sides::OneSided, ColorMode::Grayscale, false);
        assert_eq!(apply_defaults(&input, &overrides), PolicyDecision::Allow);
    }

    #[test]
    fn force_grayscale_modifies_color_job() {
        let overrides = DefaultOverrides {
            force_duplex: false,
            force_grayscale: true,
        };
        let input = make_input(Sides::TwoSidedLongEdge, ColorMode::Color, true);
        let decision = apply_defaults(&input, &overrides);
        assert!(matches!(
            decision,
            PolicyDecision::AllowWithModification { .. }
        ));
    }

    #[test]
    fn force_grayscale_allows_already_grayscale_job() {
        let overrides = DefaultOverrides {
            force_duplex: false,
            force_grayscale: true,
        };
        let input = make_input(Sides::TwoSidedLongEdge, ColorMode::Grayscale, true);
        assert_eq!(apply_defaults(&input, &overrides), PolicyDecision::Allow);
    }

    #[test]
    fn both_overrides_produce_combined_modification() {
        let overrides = DefaultOverrides {
            force_duplex: true,
            force_grayscale: true,
        };
        let input = make_input(Sides::OneSided, ColorMode::Color, true);
        let decision = apply_defaults(&input, &overrides);
        match decision {
            PolicyDecision::AllowWithModification { reason } => {
                assert!(reason.contains("duplex"));
                assert!(reason.contains("grayscale"));
            }
            other => panic!("expected AllowWithModification, got {other:?}"),
        }
    }
}
