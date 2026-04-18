// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Monthly chargeback report generation per cost center.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
//! Chargeback report generation is an auditable event (`ChargebackGenerated`).

use chrono::{DateTime, NaiveDate, Utc};
use pf_common::job::CostCenter;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AccountingError;

/// A billing period for chargeback reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingPeriod {
    /// Inclusive start date of the billing period.
    pub start: NaiveDate,
    /// Inclusive end date of the billing period.
    pub end: NaiveDate,
}

impl BillingPeriod {
    /// Create a new billing period.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidChargebackPeriod`] if the start date
    /// is after the end date.
    pub fn new(start: NaiveDate, end: NaiveDate) -> Result<Self, AccountingError> {
        if start > end {
            return Err(AccountingError::InvalidChargebackPeriod {
                message: format!("start {start} is after end {end}"),
            });
        }
        Ok(Self { start, end })
    }
}

/// A chargeback report summarizing costs for a single cost center
/// in a billing period.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargebackReport {
    /// Unique report identifier.
    pub report_id: Uuid,
    /// The cost center this report covers.
    pub cost_center: CostCenter,
    /// The billing period covered.
    pub period: BillingPeriod,
    /// Total number of print jobs in the period.
    pub total_jobs: u32,
    /// Total impressions (pages x copies) in the period.
    pub total_impressions: u32,
    /// Total color impressions in the period.
    pub color_impressions: u32,
    /// Total cost in cents for the period.
    pub total_cost_cents: u64,
    /// Breakdown of costs by category.
    pub cost_breakdown: CostBreakdown,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
}

/// Breakdown of costs by category within a chargeback report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// Total base printing costs in cents.
    pub base_cents: u64,
    /// Total color surcharges in cents.
    pub color_surcharge_cents: u64,
    /// Total media surcharges in cents.
    pub media_surcharge_cents: u64,
    /// Total finishing surcharges in cents.
    pub finishing_surcharge_cents: u64,
    /// Total duplex discounts in cents (savings).
    pub duplex_discount_cents: u64,
}

/// A line item in a chargeback report, representing a single job's cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargebackLineItem {
    /// The job identifier.
    pub job_id: String,
    /// Document name (for reference).
    pub document_name: String,
    /// Number of impressions.
    pub impressions: u32,
    /// Whether color was used.
    pub is_color: bool,
    /// Total cost for this job in cents.
    pub cost_cents: u64,
    /// When the job was completed.
    pub completed_at: DateTime<Utc>,
}

/// A single job's cost data to add to a chargeback report.
#[derive(Debug, Clone)]
pub struct ChargebackEntry {
    /// Number of impressions in the job.
    pub impressions: u32,
    /// Number of color impressions in the job.
    pub color_impressions: u32,
    /// Base printing cost in cents.
    pub base_cents: u64,
    /// Color surcharge in cents.
    pub color_surcharge_cents: u64,
    /// Media surcharge in cents.
    pub media_surcharge_cents: u64,
    /// Finishing surcharge in cents.
    pub finishing_surcharge_cents: u64,
    /// Duplex discount in cents.
    pub duplex_discount_cents: u64,
}

/// Builder for constructing a [`ChargebackReport`] from individual job costs.
#[derive(Debug)]
pub struct ChargebackReportBuilder {
    cost_center: CostCenter,
    period: BillingPeriod,
    total_jobs: u32,
    total_impressions: u32,
    color_impressions: u32,
    breakdown: CostBreakdown,
}

impl ChargebackReportBuilder {
    /// Create a new builder for a chargeback report.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidChargebackPeriod`] if the billing
    /// period is invalid.
    pub fn new(cost_center: CostCenter, period: BillingPeriod) -> Result<Self, AccountingError> {
        if period.start > period.end {
            return Err(AccountingError::InvalidChargebackPeriod {
                message: "billing period start is after end".to_string(),
            });
        }
        Ok(Self {
            cost_center,
            period,
            total_jobs: 0,
            total_impressions: 0,
            color_impressions: 0,
            breakdown: CostBreakdown::default(),
        })
    }

    /// Add a job's cost data to the report.
    pub fn add_job(&mut self, entry: &ChargebackEntry) {
        self.total_jobs += 1;
        self.total_impressions += entry.impressions;
        self.color_impressions += entry.color_impressions;
        self.breakdown.base_cents += entry.base_cents;
        self.breakdown.color_surcharge_cents += entry.color_surcharge_cents;
        self.breakdown.media_surcharge_cents += entry.media_surcharge_cents;
        self.breakdown.finishing_surcharge_cents += entry.finishing_surcharge_cents;
        self.breakdown.duplex_discount_cents += entry.duplex_discount_cents;
    }

    /// Build the final chargeback report.
    #[must_use]
    pub fn build(self) -> ChargebackReport {
        let total_cost_cents = self
            .breakdown
            .base_cents
            .saturating_add(self.breakdown.color_surcharge_cents)
            .saturating_add(self.breakdown.media_surcharge_cents)
            .saturating_add(self.breakdown.finishing_surcharge_cents)
            .saturating_sub(self.breakdown.duplex_discount_cents);

        ChargebackReport {
            report_id: Uuid::now_v7(),
            cost_center: self.cost_center,
            period: self.period,
            total_jobs: self.total_jobs,
            total_impressions: self.total_impressions,
            color_impressions: self.color_impressions,
            total_cost_cents,
            cost_breakdown: self.breakdown,
            generated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_period() -> BillingPeriod {
        BillingPeriod::new(
            NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
        )
        .unwrap()
    }

    fn test_cost_center() -> CostCenter {
        CostCenter::new("CC-100", "Test Unit").unwrap()
    }

    #[test]
    fn billing_period_rejects_inverted_dates() {
        let result = BillingPeriod::new(
            NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
            NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn billing_period_accepts_same_day() {
        let day = NaiveDate::from_ymd_opt(2026, 3, 15).unwrap();
        assert!(BillingPeriod::new(day, day).is_ok());
    }

    #[test]
    fn nist_au12_chargeback_report_generation() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        // ChargebackGenerated is an auditable event.
        let mut builder = ChargebackReportBuilder::new(test_cost_center(), test_period()).unwrap();

        builder.add_job(&ChargebackEntry {
            impressions: 100,
            color_impressions: 20,
            base_cents: 300,
            color_surcharge_cents: 240,
            media_surcharge_cents: 0,
            finishing_surcharge_cents: 0,
            duplex_discount_cents: 75,
        });
        builder.add_job(&ChargebackEntry {
            impressions: 50,
            color_impressions: 0,
            base_cents: 150,
            color_surcharge_cents: 0,
            media_surcharge_cents: 50,
            finishing_surcharge_cents: 10,
            duplex_discount_cents: 0,
        });

        let report = builder.build();

        assert_eq!(report.total_jobs, 2);
        assert_eq!(report.total_impressions, 150);
        assert_eq!(report.color_impressions, 20);
        assert_eq!(report.cost_breakdown.base_cents, 450);
        assert_eq!(report.cost_breakdown.color_surcharge_cents, 240);
        assert_eq!(report.cost_breakdown.media_surcharge_cents, 50);
        assert_eq!(report.cost_breakdown.finishing_surcharge_cents, 10);
        assert_eq!(report.cost_breakdown.duplex_discount_cents, 75);
        // 450 + 240 + 50 + 10 - 75 = 675
        assert_eq!(report.total_cost_cents, 675);
    }

    #[test]
    fn empty_report_has_zero_totals() {
        let builder = ChargebackReportBuilder::new(test_cost_center(), test_period()).unwrap();
        let report = builder.build();

        assert_eq!(report.total_jobs, 0);
        assert_eq!(report.total_impressions, 0);
        assert_eq!(report.total_cost_cents, 0);
    }
}
