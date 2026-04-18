// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Quota evaluation: monthly pages, color pages, and burst tracking.
//!
//! Quota enforcement prevents any single user or cost center from
//! consuming disproportionate print resources. Even `FleetAdmin` users
//! are subject to quota policies (with higher limits).
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, AC-6 — Least Privilege

use pf_common::job::ColorMode;
use pf_common::policy::{PolicyDecision, PolicyViolation, QuotaStatus};

use crate::input::PolicyInput;

/// Evaluate whether the user's current quota allows the requested job.
///
/// Checks both total-page and color-page quotas. Returns
/// [`PolicyDecision::Allow`] if within limits, or
/// [`PolicyDecision::Deny`] with the appropriate violation.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[must_use]
pub fn evaluate_quota(input: &PolicyInput) -> PolicyDecision {
    let total_pages = input.total_pages();

    // Check total page quota
    if total_pages > input.quota_status.remaining() {
        return PolicyDecision::Deny(PolicyViolation::QuotaExceeded);
    }

    // Check color page quota (only if the job requests color)
    if is_color_job(input) && total_pages > input.quota_status.color_remaining() {
        return PolicyDecision::Deny(PolicyViolation::ColorNotAllowed);
    }

    PolicyDecision::Allow
}

/// Determine whether a job counts as a color job for quota purposes.
///
/// `AutoDetect` is treated as color for quota accounting because the
/// actual color usage is unknown at evaluation time.
#[must_use]
const fn is_color_job(input: &PolicyInput) -> bool {
    matches!(input.color, ColorMode::Color | ColorMode::AutoDetect)
}

/// Compute how many pages remain before the user hits their quota.
#[must_use]
pub fn pages_until_quota(status: &QuotaStatus, is_color: bool) -> u32 {
    if is_color {
        status.remaining().min(status.color_remaining())
    } else {
        status.remaining()
    }
}

/// Whether a job of the given size would fit within the user's remaining
/// quota (including burst allowance).
///
/// Burst allowance is defined as 10% above the normal limit, allowing
/// users to slightly exceed their quota for urgent jobs. This is a
/// configurable policy that can be overridden per cost center.
#[must_use]
pub fn within_burst_allowance(
    status: &QuotaStatus,
    requested_pages: u32,
    burst_percent: u8,
) -> bool {
    let burst_limit = status.limit + (u32::from(burst_percent) * status.limit / 100);
    let effective_remaining = burst_limit.saturating_sub(status.used);
    requested_pages <= effective_remaining
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::fleet::PrinterId;
    use pf_common::identity::{Edipi, Role};
    use pf_common::job::{ColorMode, CostCenter, MediaSize, Sides};
    use pf_common::policy::QuotaStatus;

    use crate::input::{PolicyInput, PrinterCapabilities};

    fn make_input(
        page_count: u32,
        copies: u16,
        color: ColorMode,
        quota: QuotaStatus,
    ) -> PolicyInput {
        PolicyInput {
            user_edipi: Edipi::new("1234567890").unwrap(),
            user_roles: vec![Role::User],
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            printer_capabilities: PrinterCapabilities {
                color_supported: true,
                duplex_supported: true,
                supported_media: vec![MediaSize::Letter],
            },
            page_count,
            copies,
            sides: Sides::TwoSidedLongEdge,
            color,
            media: MediaSize::Letter,
            quota_status: quota,
        }
    }

    fn standard_quota() -> QuotaStatus {
        QuotaStatus {
            limit: 500,
            used: 400,
            color_limit: 50,
            color_used: 40,
        }
    }

    #[test]
    fn nist_ac3_allows_job_within_quota() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Job within remaining quota is allowed.
        let input = make_input(50, 1, ColorMode::Grayscale, standard_quota());
        assert_eq!(evaluate_quota(&input), PolicyDecision::Allow);
    }

    #[test]
    fn nist_ac3_denies_job_exceeding_total_quota() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Job exceeding total page quota is denied.
        let input = make_input(200, 1, ColorMode::Grayscale, standard_quota());
        assert_eq!(
            evaluate_quota(&input),
            PolicyDecision::Deny(PolicyViolation::QuotaExceeded)
        );
    }

    #[test]
    fn nist_ac3_denies_color_job_exceeding_color_quota() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: Color job exceeding color quota is denied.
        let input = make_input(20, 1, ColorMode::Color, standard_quota());
        assert_eq!(
            evaluate_quota(&input),
            PolicyDecision::Deny(PolicyViolation::ColorNotAllowed)
        );
    }

    #[test]
    fn auto_detect_treated_as_color_for_quota() {
        let input = make_input(20, 1, ColorMode::AutoDetect, standard_quota());
        assert_eq!(
            evaluate_quota(&input),
            PolicyDecision::Deny(PolicyViolation::ColorNotAllowed)
        );
    }

    #[test]
    fn grayscale_job_ignores_color_quota() {
        let quota = QuotaStatus {
            limit: 500,
            used: 0,
            color_limit: 50,
            color_used: 50, // color quota exhausted
        };
        let input = make_input(10, 1, ColorMode::Grayscale, quota);
        assert_eq!(evaluate_quota(&input), PolicyDecision::Allow);
    }

    #[test]
    fn copies_multiplied_in_quota_check() {
        // 50 pages * 3 copies = 150 pages, but only 100 remaining
        let input = make_input(50, 3, ColorMode::Grayscale, standard_quota());
        assert_eq!(
            evaluate_quota(&input),
            PolicyDecision::Deny(PolicyViolation::QuotaExceeded)
        );
    }

    #[test]
    fn pages_until_quota_for_grayscale() {
        let status = standard_quota();
        assert_eq!(pages_until_quota(&status, false), 100);
    }

    #[test]
    fn pages_until_quota_for_color_uses_minimum() {
        let status = standard_quota();
        // color remaining = 10, total remaining = 100 -> min is 10
        assert_eq!(pages_until_quota(&status, true), 10);
    }

    #[test]
    fn burst_allowance_permits_slight_overage() {
        let status = QuotaStatus {
            limit: 100,
            used: 95,
            color_limit: 50,
            color_used: 0,
        };
        // 10% burst: effective limit = 110, remaining = 15
        assert!(within_burst_allowance(&status, 15, 10));
        assert!(!within_burst_allowance(&status, 16, 10));
    }

    #[test]
    fn burst_allowance_zero_percent_is_strict() {
        let status = QuotaStatus {
            limit: 100,
            used: 95,
            color_limit: 50,
            color_used: 0,
        };
        assert!(within_burst_allowance(&status, 5, 0));
        assert!(!within_burst_allowance(&status, 6, 0));
    }
}
