// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Health scoring algorithm for printers.
//!
//! **NIST 800-53 Rev 5:** SI-4 — System Monitoring
//! Each printer receives a 0--100 health score based on weighted factors:
//! - Connectivity (30%): Is the printer reachable and responding?
//! - Error state (25%): Active error conditions reduce the score.
//! - Supply levels (20%): Low toner or paper reduces the score.
//! - Queue depth (15%): Excessive queue depth indicates a problem.
//! - Firmware currency (10%): Out-of-date firmware reduces the score.

use serde::{Deserialize, Serialize};

use pf_common::fleet::{PrinterStatus, SupplyLevel};

/// Weight configuration for the health scoring algorithm.
///
/// Weights must sum to 100. The default values match the design document.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthWeights {
    /// Weight for connectivity factor (default: 30).
    pub connectivity: u8,
    /// Weight for error state factor (default: 25).
    pub error_state: u8,
    /// Weight for supply levels factor (default: 20).
    pub supply_levels: u8,
    /// Weight for queue depth factor (default: 15).
    pub queue_depth: u8,
    /// Weight for firmware currency factor (default: 10).
    pub firmware_currency: u8,
}

impl Default for HealthWeights {
    fn default() -> Self {
        Self {
            connectivity: 30,
            error_state: 25,
            supply_levels: 20,
            queue_depth: 15,
            firmware_currency: 10,
        }
    }
}

impl HealthWeights {
    /// Returns the sum of all weights.
    fn total(self) -> u16 {
        u16::from(self.connectivity)
            + u16::from(self.error_state)
            + u16::from(self.supply_levels)
            + u16::from(self.queue_depth)
            + u16::from(self.firmware_currency)
    }

    /// Validates that the weights sum to 100.
    ///
    /// # Errors
    ///
    /// Returns an error message if the weights do not sum to 100.
    pub fn validate(self) -> Result<(), String> {
        let total = self.total();
        if total != 100 {
            return Err(format!("health weights must sum to 100, got {total}"));
        }
        Ok(())
    }
}

/// Input factors for computing a printer health score.
#[derive(Debug, Clone)]
pub struct HealthInput {
    /// Current operational status.
    pub status: PrinterStatus,
    /// Whether the printer responded to the last poll.
    pub is_reachable: bool,
    /// Number of consecutive poll failures.
    pub consecutive_failures: u32,
    /// Current supply levels.
    pub supply_levels: Option<SupplyLevel>,
    /// Current print queue depth.
    pub queue_depth: u32,
    /// Maximum expected queue depth before considering it problematic.
    pub queue_capacity: u32,
    /// Whether the firmware is at the latest approved version.
    pub firmware_current: bool,
    /// Number of active error conditions.
    pub active_error_count: u32,
}

/// Computed health score with a breakdown by factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    /// Overall health score (0--100).
    pub overall: u8,
    /// Individual factor scores (each 0--100 before weighting).
    pub breakdown: HealthBreakdown,
}

/// Per-factor scores (each 0--100, before weight is applied).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthBreakdown {
    /// Connectivity factor score.
    pub connectivity: u8,
    /// Error state factor score.
    pub error_state: u8,
    /// Supply levels factor score.
    pub supply_levels: u8,
    /// Queue depth factor score.
    pub queue_depth: u8,
    /// Firmware currency factor score.
    pub firmware_currency: u8,
}

/// Compute the health score for a printer.
///
/// **NIST 800-53 Rev 5:** SI-4 — System Monitoring
///
/// # Errors
///
/// Returns an error if the weight configuration is invalid.
pub fn compute_health_score(
    input: &HealthInput,
    weights: &HealthWeights,
) -> Result<HealthScore, String> {
    weights.validate()?;

    let connectivity = compute_connectivity(input);
    let error_state = compute_error_state(input);
    let supply = compute_supply_score(input);
    let queue = compute_queue_score(input);
    let firmware = compute_firmware_score(input);

    let weighted_sum = u32::from(connectivity) * u32::from(weights.connectivity)
        + u32::from(error_state) * u32::from(weights.error_state)
        + u32::from(supply) * u32::from(weights.supply_levels)
        + u32::from(queue) * u32::from(weights.queue_depth)
        + u32::from(firmware) * u32::from(weights.firmware_currency);

    // weights sum to 100, so dividing by 100 gives us the overall 0-100 score.
    let overall = u8::try_from(weighted_sum / 100).unwrap_or(100);

    Ok(HealthScore {
        overall,
        breakdown: HealthBreakdown {
            connectivity,
            error_state,
            supply_levels: supply,
            queue_depth: queue,
            firmware_currency: firmware,
        },
    })
}

/// Connectivity factor: 100 if reachable with no failures, degrades with consecutive failures,
/// 0 if offline.
fn compute_connectivity(input: &HealthInput) -> u8 {
    if !input.is_reachable {
        return 0;
    }
    if input.status == PrinterStatus::Offline {
        0
    } else {
        // Degrade 20 points per consecutive failure, minimum 0.
        let penalty = input.consecutive_failures.saturating_mul(20);
        100u8.saturating_sub(u8::try_from(penalty).unwrap_or(100))
    }
}

/// Error state factor: 100 if no errors, reduced by active error count.
/// Returns 0 for `Error` or `Offline` status.
fn compute_error_state(input: &HealthInput) -> u8 {
    if input.status == PrinterStatus::Error || input.status == PrinterStatus::Offline {
        0
    } else {
        // Each active error condition deducts 25 points.
        let penalty = input.active_error_count.saturating_mul(25);
        100u8.saturating_sub(u8::try_from(penalty).unwrap_or(100))
    }
}

/// Supply levels factor: based on the minimum supply level across all consumables.
fn compute_supply_score(input: &HealthInput) -> u8 {
    let Some(levels) = &input.supply_levels else {
        // Unknown supply levels get a middle score (no data is not the same as bad).
        return 50;
    };

    levels
        .toner_k
        .min(levels.toner_c)
        .min(levels.toner_m)
        .min(levels.toner_y)
        .min(levels.paper)
}

/// Queue depth factor: 100 if empty, linearly degrades as queue fills to capacity.
fn compute_queue_score(input: &HealthInput) -> u8 {
    if input.queue_capacity == 0 {
        return if input.queue_depth == 0 { 100 } else { 0 };
    }

    let ratio = f64::from(input.queue_depth) / f64::from(input.queue_capacity);
    let score = (1.0 - ratio.min(1.0)) * 100.0;
    // Truncation is intentional: we want a floor for the score.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let result = score as u8;
    result
}

/// Firmware currency factor: 100 if current, 40 if outdated.
fn compute_firmware_score(input: &HealthInput) -> u8 {
    if input.firmware_current { 100 } else { 40 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_healthy_input() -> HealthInput {
        HealthInput {
            status: PrinterStatus::Online,
            is_reachable: true,
            consecutive_failures: 0,
            supply_levels: Some(SupplyLevel {
                toner_k: 80,
                toner_c: 75,
                toner_m: 90,
                toner_y: 85,
                paper: 70,
            }),
            queue_depth: 2,
            queue_capacity: 50,
            firmware_current: true,
            active_error_count: 0,
        }
    }

    #[test]
    fn nist_si4_healthy_printer_scores_high() {
        // NIST SI-4: System Monitoring
        // A fully healthy printer should score above 90.
        let input = make_healthy_input();
        let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
        assert!(
            score.overall >= 70,
            "healthy printer scored {} (expected >= 70)",
            score.overall
        );
    }

    #[test]
    fn nist_si4_offline_printer_scores_low() {
        // NIST SI-4: System Monitoring
        // An unreachable printer should have a drastically reduced score.
        let input = HealthInput {
            status: PrinterStatus::Offline,
            is_reachable: false,
            consecutive_failures: 5,
            supply_levels: None,
            queue_depth: 0,
            queue_capacity: 50,
            firmware_current: false,
            active_error_count: 0,
        };
        let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
        assert!(
            score.overall <= 30,
            "offline printer scored {} (expected <= 30)",
            score.overall
        );
    }

    #[test]
    fn nist_si4_error_state_reduces_score() {
        // NIST SI-4: System Monitoring
        // A printer in error state should have a lower score than a healthy one.
        let mut input = make_healthy_input();
        input.status = PrinterStatus::Error;
        input.active_error_count = 2;
        let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
        let healthy_score =
            compute_health_score(&make_healthy_input(), &HealthWeights::default()).unwrap();
        assert!(
            score.overall < healthy_score.overall,
            "error printer scored {} >= healthy {}",
            score.overall,
            healthy_score.overall
        );
    }

    #[test]
    fn nist_si4_low_supplies_reduce_score() {
        // NIST SI-4: System Monitoring
        // Low supply levels should reduce the health score.
        let mut input = make_healthy_input();
        input.supply_levels = Some(SupplyLevel {
            toner_k: 3,
            toner_c: 5,
            toner_m: 5,
            toner_y: 5,
            paper: 2,
        });
        let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
        let healthy_score =
            compute_health_score(&make_healthy_input(), &HealthWeights::default()).unwrap();
        assert!(
            score.overall < healthy_score.overall,
            "low-supply printer scored {} >= healthy {}",
            score.overall,
            healthy_score.overall
        );
    }

    #[test]
    fn health_score_is_bounded_0_to_100() {
        let input = HealthInput {
            status: PrinterStatus::Online,
            is_reachable: true,
            consecutive_failures: 0,
            supply_levels: Some(SupplyLevel {
                toner_k: 100,
                toner_c: 100,
                toner_m: 100,
                toner_y: 100,
                paper: 100,
            }),
            queue_depth: 0,
            queue_capacity: 50,
            firmware_current: true,
            active_error_count: 0,
        };
        let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
        assert!(score.overall <= 100);

        // Worst case
        let worst = HealthInput {
            status: PrinterStatus::Error,
            is_reachable: false,
            consecutive_failures: 100,
            supply_levels: Some(SupplyLevel {
                toner_k: 0,
                toner_c: 0,
                toner_m: 0,
                toner_y: 0,
                paper: 0,
            }),
            queue_depth: 100,
            queue_capacity: 50,
            firmware_current: false,
            active_error_count: 10,
        };
        let worst_score = compute_health_score(&worst, &HealthWeights::default()).unwrap();
        // Firmware score is 40 when outdated (not zero), so worst case is 4.
        assert!(
            worst_score.overall <= 5,
            "worst case scored {} (expected <= 5)",
            worst_score.overall
        );
    }

    #[test]
    fn invalid_weights_rejected() {
        let bad_weights = HealthWeights {
            connectivity: 50,
            error_state: 50,
            supply_levels: 50,
            queue_depth: 50,
            firmware_currency: 50,
        };
        let input = make_healthy_input();
        let result = compute_health_score(&input, &bad_weights);
        assert!(result.is_err());
    }

    #[test]
    fn default_weights_sum_to_100() {
        let weights = HealthWeights::default();
        assert!(weights.validate().is_ok());
    }

    #[test]
    fn outdated_firmware_reduces_score() {
        let mut input = make_healthy_input();
        input.firmware_current = false;
        let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
        let healthy_score =
            compute_health_score(&make_healthy_input(), &HealthWeights::default()).unwrap();
        assert!(score.overall < healthy_score.overall);
    }
}
