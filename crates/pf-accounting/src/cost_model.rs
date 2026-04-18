// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Per-job cost calculation.
//!
//! **Formula:** Job Cost = (Pages x Copies) x (Base + `ColorSurcharge` + `MediaSurcharge`
//! + `FinishingSurcharge`) x (1 - `DuplexDiscount`)
//!
//! All values are configurable via cost tables. Costs are tracked in US cents
//! (integer arithmetic) to avoid floating-point rounding issues.

use chrono::{DateTime, Utc};
use pf_common::job::{ColorMode, CostCenter, JobId, MediaSize, PrintOptions, Sides};
use serde::{Deserialize, Serialize};

use crate::config::CostTableConfig;

/// A set of finishing options that may apply surcharges.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinishingOptions {
    /// Whether stapling was requested.
    pub staple: bool,
    /// Whether hole-punch was requested.
    pub punch: bool,
}

/// Input parameters for a cost calculation.
#[derive(Debug, Clone)]
pub struct CostInput {
    /// The print job identifier.
    pub job_id: JobId,
    /// Number of pages in the document.
    pub page_count: u32,
    /// User-selected (or default) print options.
    pub options: PrintOptions,
    /// Optional finishing options (staple, punch).
    pub finishing: FinishingOptions,
    /// The cost center to charge.
    pub cost_center: CostCenter,
    /// The installation code (for cost table resolution).
    pub installation_code: String,
}

/// The calculated cost breakdown for a single print job.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
/// Cost assignment is an auditable event (`CostAssigned`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCost {
    /// The print job identifier.
    pub job_id: JobId,
    /// The cost center charged.
    pub cost_center: CostCenter,
    /// Total impressions: pages x copies.
    pub total_impressions: u32,
    /// Base cost component in cents.
    pub base_cost_cents: u64,
    /// Color surcharge component in cents.
    pub color_surcharge_cents: u64,
    /// Media surcharge component in cents.
    pub media_surcharge_cents: u64,
    /// Finishing surcharge component in cents.
    pub finishing_surcharge_cents: u64,
    /// Duplex discount component in cents (subtracted).
    pub duplex_discount_cents: u64,
    /// Final total cost in cents.
    pub total_cost_cents: u64,
    /// Whether this is an estimate (at submission) or final (at completion).
    pub is_estimate: bool,
    /// Timestamp of the cost calculation.
    pub calculated_at: DateTime<Utc>,
}

/// Calculate the cost for a print job given a cost table configuration.
///
/// # Errors
///
/// This function is infallible for valid inputs. All cost table values
/// are unsigned, so negative costs cannot occur.
#[must_use]
pub fn calculate_job_cost(
    input: &CostInput,
    table: &CostTableConfig,
    is_estimate: bool,
) -> JobCost {
    let impressions = u64::from(input.page_count) * u64::from(input.options.copies);

    // Base cost
    let base = impressions * u64::from(table.base_cost_cents);

    // Color surcharge
    let color = match input.options.color {
        ColorMode::Color => impressions * u64::from(table.color_surcharge_cents),
        ColorMode::Grayscale | ColorMode::AutoDetect => 0,
    };

    // Media surcharge
    let media = impressions * u64::from(media_surcharge(input.options.media, table));

    // Finishing surcharges
    let finishing = impressions * u64::from(finishing_surcharge(&input.finishing, table));

    // Subtotal before duplex discount
    let subtotal = base + color + media + finishing;

    // Duplex discount
    let duplex_discount = if is_duplex(input.options.sides) {
        subtotal * u64::from(table.duplex_discount_pct) / 100
    } else {
        0
    };

    let total = subtotal.saturating_sub(duplex_discount);

    JobCost {
        job_id: input.job_id.clone(),
        cost_center: input.cost_center.clone(),
        total_impressions: u32::try_from(impressions).unwrap_or(u32::MAX),
        base_cost_cents: base,
        color_surcharge_cents: color,
        media_surcharge_cents: media,
        finishing_surcharge_cents: finishing,
        duplex_discount_cents: duplex_discount,
        total_cost_cents: total,
        is_estimate,
        calculated_at: Utc::now(),
    }
}

/// Look up the media surcharge for a given media size.
const fn media_surcharge(media: MediaSize, table: &CostTableConfig) -> u32 {
    match media {
        MediaSize::Letter => 0,
        MediaSize::Legal => table.legal_surcharge_cents,
        MediaSize::Ledger => table.ledger_surcharge_cents,
        MediaSize::A3 => table.a3_surcharge_cents,
        MediaSize::A4 => table.a4_surcharge_cents,
    }
}

/// Calculate the total finishing surcharge per page.
const fn finishing_surcharge(finishing: &FinishingOptions, table: &CostTableConfig) -> u32 {
    let mut surcharge = 0;
    if finishing.staple {
        surcharge += table.staple_surcharge_cents;
    }
    if finishing.punch {
        surcharge += table.punch_surcharge_cents;
    }
    surcharge
}

/// Check whether the sides setting is duplex.
const fn is_duplex(sides: Sides) -> bool {
    matches!(sides, Sides::TwoSidedLongEdge | Sides::TwoSidedShortEdge)
}

#[cfg(test)]
mod tests {
    use pf_common::job::CostCenter;

    use super::*;

    fn test_input(
        pages: u32,
        copies: u16,
        color: ColorMode,
        media: MediaSize,
        sides: Sides,
    ) -> CostInput {
        CostInput {
            job_id: JobId::generate(),
            page_count: pages,
            options: PrintOptions {
                copies,
                sides,
                color,
                media,
            },
            finishing: FinishingOptions::default(),
            cost_center: CostCenter::new("CC-001", "Test Center").unwrap(),
            installation_code: "TEST".to_string(),
        }
    }

    #[test]
    fn basic_grayscale_letter_simplex_cost() {
        let input = test_input(
            10,
            1,
            ColorMode::Grayscale,
            MediaSize::Letter,
            Sides::OneSided,
        );
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 10 pages x 1 copy x 3 cents base = 30 cents, no surcharges, no discount
        assert_eq!(cost.total_impressions, 10);
        assert_eq!(cost.base_cost_cents, 30);
        assert_eq!(cost.color_surcharge_cents, 0);
        assert_eq!(cost.media_surcharge_cents, 0);
        assert_eq!(cost.duplex_discount_cents, 0);
        assert_eq!(cost.total_cost_cents, 30);
    }

    #[test]
    fn color_surcharge_applied() {
        let input = test_input(10, 1, ColorMode::Color, MediaSize::Letter, Sides::OneSided);
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 10 x (3 base + 12 color) = 150 cents
        assert_eq!(cost.total_cost_cents, 150);
        assert_eq!(cost.color_surcharge_cents, 120);
    }

    #[test]
    fn duplex_discount_applied() {
        let input = test_input(
            10,
            1,
            ColorMode::Grayscale,
            MediaSize::Letter,
            Sides::TwoSidedLongEdge,
        );
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 10 x 3 = 30 subtotal, 25% discount = 7 (integer division), total = 23
        assert_eq!(cost.base_cost_cents, 30);
        assert_eq!(cost.duplex_discount_cents, 7);
        assert_eq!(cost.total_cost_cents, 23);
    }

    #[test]
    fn copies_multiply_cost() {
        let input = test_input(
            5,
            3,
            ColorMode::Grayscale,
            MediaSize::Letter,
            Sides::OneSided,
        );
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 5 pages x 3 copies x 3 cents = 45
        assert_eq!(cost.total_impressions, 15);
        assert_eq!(cost.total_cost_cents, 45);
    }

    #[test]
    fn media_surcharge_for_legal() {
        let input = test_input(
            10,
            1,
            ColorMode::Grayscale,
            MediaSize::Legal,
            Sides::OneSided,
        );
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 10 x (3 base + 1 legal surcharge) = 40
        assert_eq!(cost.media_surcharge_cents, 10);
        assert_eq!(cost.total_cost_cents, 40);
    }

    #[test]
    fn finishing_surcharges_applied() {
        let mut input = test_input(
            10,
            1,
            ColorMode::Grayscale,
            MediaSize::Letter,
            Sides::OneSided,
        );
        input.finishing = FinishingOptions {
            staple: true,
            punch: true,
        };
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 10 x (3 base + 1 staple + 1 punch) = 50
        assert_eq!(cost.finishing_surcharge_cents, 20);
        assert_eq!(cost.total_cost_cents, 50);
    }

    #[test]
    fn combined_surcharges_and_discount() {
        let mut input = test_input(
            10,
            2,
            ColorMode::Color,
            MediaSize::Ledger,
            Sides::TwoSidedShortEdge,
        );
        input.finishing = FinishingOptions {
            staple: true,
            punch: false,
        };
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        // 20 impressions x (3 base + 12 color + 3 ledger + 1 staple) = 20 x 19 = 380
        // 25% duplex discount = 95
        // Total = 285
        assert_eq!(cost.total_impressions, 20);
        assert_eq!(cost.base_cost_cents, 60);
        assert_eq!(cost.color_surcharge_cents, 240);
        assert_eq!(cost.media_surcharge_cents, 60);
        assert_eq!(cost.finishing_surcharge_cents, 20);
        assert_eq!(cost.duplex_discount_cents, 95);
        assert_eq!(cost.total_cost_cents, 285);
    }

    #[test]
    fn zero_pages_produces_zero_cost() {
        let input = test_input(0, 1, ColorMode::Color, MediaSize::Letter, Sides::OneSided);
        let table = CostTableConfig::default();
        let cost = calculate_job_cost(&input, &table, false);

        assert_eq!(cost.total_cost_cents, 0);
    }

    #[test]
    fn estimate_flag_set_correctly() {
        let input = test_input(
            1,
            1,
            ColorMode::Grayscale,
            MediaSize::Letter,
            Sides::OneSided,
        );
        let table = CostTableConfig::default();

        let estimate = calculate_job_cost(&input, &table, true);
        assert!(estimate.is_estimate);

        let final_cost = calculate_job_cost(&input, &table, false);
        assert!(!final_cost.is_estimate);
    }
}
