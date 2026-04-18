// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Core policy evaluation logic.
//!
//! The [`evaluate_job`] function is the primary entry point for the policy
//! engine. It aggregates results from quota checks, default enforcement,
//! and `OPA` / embedded evaluation into a single [`PolicyDecision`].
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, CM-7 — Least Functionality
//!
//! **Default-deny:** If any evaluation step fails or is unreachable, the
//! job is held (denied). This is the fail-closed pattern required by
//! organizational policy.

use pf_common::policy::{PolicyDecision, PolicyViolation};
use tracing::{info, warn};

use crate::defaults::{DefaultOverrides, apply_defaults};
use crate::error::PolicyError;
use crate::input::PolicyInput;
use crate::quota::evaluate_quota;

/// Evaluate a print job against all applicable policies.
///
/// This function implements the **default-deny** pattern: if any evaluation
/// step fails, the job is denied. The evaluation order is:
///
/// 1. Input validation
/// 2. Quota enforcement (page limits, color limits)
/// 3. Default print-settings enforcement (duplex, grayscale)
/// 4. `OPA` / embedded policy evaluation (delegated to caller)
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns [`PolicyError`] if input validation fails. All other failures
/// result in a [`PolicyDecision::Deny`] with an appropriate violation
/// rather than an error, implementing fail-closed behavior.
pub fn evaluate_job(
    input: &PolicyInput,
    page_limit: u32,
    overrides: &DefaultOverrides,
) -> Result<PolicyDecision, PolicyError> {
    // Step 1: Validate input
    input.validate()?;

    // Step 2: Check quotas
    let quota_decision = evaluate_quota(input);
    if let PolicyDecision::Deny(ref violation) = quota_decision {
        info!(
            violation = ?violation,
            "policy denied job: quota violation"
        );
        return Ok(quota_decision);
    }

    // Step 3: Check page limit
    let total = input.total_pages();
    if total > page_limit {
        info!(
            total_pages = total,
            limit = page_limit,
            "policy denied job: page limit exceeded"
        );
        return Ok(PolicyDecision::Deny(PolicyViolation::PageLimitExceeded {
            limit: page_limit,
            requested: total,
        }));
    }

    // Step 4: Apply default overrides (may modify the decision)
    let defaults_decision = apply_defaults(input, overrides);
    if defaults_decision != PolicyDecision::Allow {
        info!(
            decision = ?defaults_decision,
            "policy applied default overrides"
        );
        return Ok(defaults_decision);
    }

    // All local checks passed
    Ok(PolicyDecision::Allow)
}

/// Evaluate a job with the **default-deny** fallback.
///
/// Wraps [`evaluate_job`] and converts any [`PolicyError`] into a
/// [`PolicyDecision::Deny`], ensuring that failures always result in
/// the job being held rather than released.
///
/// **NIST 800-53 Rev 5:** CM-7 — Least Functionality (fail closed)
///
/// # Errors
///
/// This function never returns an error. All errors are converted to deny
/// decisions.
pub fn evaluate_job_default_deny(
    input: &PolicyInput,
    page_limit: u32,
    overrides: &DefaultOverrides,
) -> PolicyDecision {
    match evaluate_job(input, page_limit, overrides) {
        Ok(decision) => decision,
        Err(e) => {
            warn!(
                error = %e,
                "policy evaluation failed, defaulting to deny (fail closed)"
            );
            PolicyDecision::Deny(PolicyViolation::Custom {
                rule: "default_deny".to_string(),
                message: "policy evaluation unavailable".to_string(),
            })
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

    use crate::defaults::DefaultOverrides;
    use crate::input::{PolicyInput, PrinterCapabilities};

    fn sample_input(page_count: u32, copies: u16, color: ColorMode) -> PolicyInput {
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
            quota_status: QuotaStatus {
                limit: 500,
                used: 100,
                color_limit: 50,
                color_used: 10,
            },
        }
    }

    fn default_overrides() -> DefaultOverrides {
        DefaultOverrides {
            force_duplex: false,
            force_grayscale: false,
        }
    }

    #[test]
    fn nist_ac3_allows_valid_job_within_quota() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: A valid job within quota and page limits is allowed.
        let input = sample_input(10, 1, ColorMode::Grayscale);
        let decision = evaluate_job(&input, 500, &default_overrides()).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn nist_cm7_denies_when_page_limit_exceeded() {
        // NIST 800-53 Rev 5: CM-7 — Least Functionality
        // Evidence: A job exceeding page limits is denied.
        // Use a high quota so the page-limit check is the one that triggers.
        let mut input = sample_input(100, 10, ColorMode::Grayscale);
        input.quota_status = QuotaStatus {
            limit: 5000,
            used: 0,
            color_limit: 500,
            color_used: 0,
        };
        let decision = evaluate_job(&input, 500, &default_overrides()).unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::Deny(PolicyViolation::PageLimitExceeded { .. })
        ));
    }

    #[test]
    fn nist_cm7_denies_when_quota_exceeded() {
        // NIST 800-53 Rev 5: CM-7 — Least Functionality
        // Evidence: A job exceeding the user's quota is denied.
        let mut input = sample_input(10, 1, ColorMode::Grayscale);
        input.quota_status = QuotaStatus {
            limit: 100,
            used: 100,
            color_limit: 50,
            color_used: 10,
        };
        let decision = evaluate_job(&input, 500, &default_overrides()).unwrap();
        assert_eq!(
            decision,
            PolicyDecision::Deny(PolicyViolation::QuotaExceeded)
        );
    }

    #[test]
    fn nist_cm7_default_deny_on_invalid_input() {
        // NIST 800-53 Rev 5: CM-7 — Least Functionality (fail closed)
        // Evidence: Invalid input results in a deny decision, not a crash.
        let input = sample_input(0, 1, ColorMode::Grayscale);
        let decision = evaluate_job_default_deny(&input, 500, &default_overrides());
        assert!(matches!(
            decision,
            PolicyDecision::Deny(PolicyViolation::Custom { .. })
        ));
    }

    #[test]
    fn nist_cm7_default_deny_converts_errors_to_deny() {
        // NIST 800-53 Rev 5: CM-7 — Least Functionality (fail closed)
        // Evidence: A zero-page-count job is denied by the default-deny wrapper.
        let input = sample_input(0, 0, ColorMode::Grayscale);
        let decision = evaluate_job_default_deny(&input, 500, &default_overrides());
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn applies_force_duplex_override() {
        let input = sample_input(10, 1, ColorMode::Grayscale);
        let overrides = DefaultOverrides {
            force_duplex: true,
            force_grayscale: false,
        };
        let decision = evaluate_job(&input, 500, &overrides).unwrap();
        // The input already has duplex, so no modification needed
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn applies_force_grayscale_override_on_color_job() {
        let input = sample_input(10, 1, ColorMode::Color);
        let overrides = DefaultOverrides {
            force_duplex: false,
            force_grayscale: true,
        };
        let decision = evaluate_job(&input, 500, &overrides).unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::AllowWithModification { .. }
        ));
    }
}
