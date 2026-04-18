// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Property-based tests for `pf-policy-engine` policy evaluation.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement

use proptest::prelude::*;

use pf_common::fleet::PrinterId;
use pf_common::identity::{Edipi, Role};
use pf_common::job::{ColorMode, CostCenter, MediaSize, Sides};
use pf_common::policy::{PolicyDecision, PolicyViolation, QuotaStatus};

use pf_policy_engine::input::{PolicyInput, PrinterCapabilities};
use pf_policy_engine::quota::evaluate_quota;

/// Build a `PolicyInput` with the given `page_count`, copies, and quota.
fn make_policy_input(page_count: u32, copies: u16, quota: QuotaStatus) -> PolicyInput {
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
        color: ColorMode::Grayscale,
        media: MediaSize::Letter,
        quota_status: quota,
    }
}

proptest! {
    /// `total_pages()` with arbitrary `u32` page_count and `u16` copies
    /// must never overflow or panic — it uses saturating multiplication.
    #[test]
    fn prop_total_pages_never_overflows(page_count in any::<u32>(), copies in any::<u16>()) {
        let quota = QuotaStatus {
            limit: u32::MAX,
            used: 0,
            color_limit: u32::MAX,
            color_used: 0,
        };
        let input = make_policy_input(page_count, copies, quota);
        // Must not panic — saturating arithmetic ensures no overflow.
        let total = input.total_pages();
        // Verify the result is sane: at most page_count * copies (saturated).
        let expected = page_count.saturating_mul(u32::from(copies));
        prop_assert_eq!(total, expected);
    }

    /// When the user's quota is fully consumed (`used >= limit`), any
    /// positive page count must be denied by `evaluate_quota`.
    #[test]
    fn prop_quota_exceeded_always_denied(
        used in 100u32..=u32::MAX,
        page_count in 1u32..=10_000,
        copies in 1u16..=100,
    ) {
        let limit = 100u32;
        // Ensure used >= limit so remaining == 0.
        let quota = QuotaStatus {
            limit,
            used,
            color_limit: 1000,
            color_used: 0,
        };
        let input = make_policy_input(page_count, copies, quota);
        let decision = evaluate_quota(&input);
        prop_assert_eq!(
            decision,
            PolicyDecision::Deny(PolicyViolation::QuotaExceeded),
            "Expected deny when used={} >= limit={}, pages={}, copies={}",
            used, limit, page_count, copies,
        );
    }
}
