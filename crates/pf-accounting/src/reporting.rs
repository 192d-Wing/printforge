// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Report types for fleet utilization, quota compliance, and waste reduction.
//!
//! These types are consumed by `pf-admin-ui` for executive dashboards
//! and RM&A (Resource Management & Analysis) reporting.

use chrono::{DateTime, Utc};
use pf_common::job::CostCenter;
use serde::{Deserialize, Serialize};

use crate::chargeback::BillingPeriod;

/// Fleet utilization report summarizing printing activity across installations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetUtilizationReport {
    /// The billing period covered by this report.
    pub period: BillingPeriod,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
    /// Per-installation utilization summaries.
    pub installations: Vec<InstallationUtilization>,
    /// Fleet-wide totals.
    pub fleet_totals: UtilizationSummary,
}

/// Utilization summary for a single installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationUtilization {
    /// Installation code (e.g., "JBSA", "WPAFB").
    pub installation_code: String,
    /// Installation name.
    pub installation_name: String,
    /// Utilization metrics.
    pub summary: UtilizationSummary,
}

/// Aggregated utilization metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtilizationSummary {
    /// Total print jobs in the period.
    pub total_jobs: u64,
    /// Total impressions (pages x copies).
    pub total_impressions: u64,
    /// Total color impressions.
    pub color_impressions: u64,
    /// Total cost in cents.
    pub total_cost_cents: u64,
    /// Total duplex savings in cents.
    pub duplex_savings_cents: u64,
    /// Number of unique users who printed.
    pub unique_users: u32,
    /// Average cost per job in cents.
    pub avg_cost_per_job_cents: u64,
}

/// Quota compliance report showing users' adherence to printing quotas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaComplianceReport {
    /// The billing period covered by this report.
    pub period: BillingPeriod,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
    /// Per-cost-center quota compliance summaries.
    pub cost_centers: Vec<CostCenterCompliance>,
    /// Fleet-wide compliance summary.
    pub fleet_summary: ComplianceSummary,
}

/// Quota compliance summary for a single cost center.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostCenterCompliance {
    /// The cost center.
    pub cost_center: CostCenter,
    /// Number of users in this cost center.
    pub total_users: u32,
    /// Number of users within their quota.
    pub users_within_quota: u32,
    /// Number of users who exceeded their quota (but within burst).
    pub users_in_burst: u32,
    /// Number of users who exceeded their quota including burst.
    pub users_over_quota: u32,
    /// Total pages consumed.
    pub total_pages_used: u64,
    /// Total pages allocated.
    pub total_pages_allocated: u64,
}

/// Fleet-wide compliance summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Total users across all cost centers.
    pub total_users: u32,
    /// Users within standard quota.
    pub users_within_quota: u32,
    /// Users in burst range.
    pub users_in_burst: u32,
    /// Users over all limits.
    pub users_over_quota: u32,
    /// Compliance rate as percentage (0-100).
    pub compliance_rate_pct: u8,
}

/// Waste reduction report tracking duplex adoption and color reduction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasteReductionReport {
    /// The billing period covered by this report.
    pub period: BillingPeriod,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
    /// Duplex printing adoption metrics.
    pub duplex_metrics: DuplexMetrics,
    /// Color reduction metrics.
    pub color_metrics: ColorMetrics,
    /// Estimated cost savings from duplex and grayscale usage.
    pub estimated_savings_cents: u64,
}

/// Duplex printing adoption metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DuplexMetrics {
    /// Total jobs that used duplex printing.
    pub duplex_jobs: u64,
    /// Total jobs that used simplex printing.
    pub simplex_jobs: u64,
    /// Duplex adoption rate as percentage (0-100).
    pub adoption_rate_pct: u8,
    /// Estimated pages saved by duplex printing.
    pub pages_saved: u64,
}

/// Color printing reduction metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ColorMetrics {
    /// Total color jobs.
    pub color_jobs: u64,
    /// Total grayscale jobs.
    pub grayscale_jobs: u64,
    /// Color usage rate as percentage (0-100).
    pub color_rate_pct: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn utilization_summary_default_is_zero() {
        let summary = UtilizationSummary::default();
        assert_eq!(summary.total_jobs, 0);
        assert_eq!(summary.total_cost_cents, 0);
    }

    #[test]
    fn compliance_summary_default_is_zero() {
        let summary = ComplianceSummary::default();
        assert_eq!(summary.total_users, 0);
        assert_eq!(summary.compliance_rate_pct, 0);
    }

    #[test]
    fn duplex_metrics_default_is_zero() {
        let metrics = DuplexMetrics::default();
        assert_eq!(metrics.duplex_jobs, 0);
        assert_eq!(metrics.adoption_rate_pct, 0);
    }

    #[test]
    fn report_types_are_serializable() {
        let period = BillingPeriod::new(
            NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
        )
        .unwrap();

        let report = WasteReductionReport {
            period,
            generated_at: Utc::now(),
            duplex_metrics: DuplexMetrics {
                duplex_jobs: 300,
                simplex_jobs: 100,
                adoption_rate_pct: 75,
                pages_saved: 1500,
            },
            color_metrics: ColorMetrics {
                color_jobs: 50,
                grayscale_jobs: 350,
                color_rate_pct: 12,
            },
            estimated_savings_cents: 45_000,
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: WasteReductionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.duplex_metrics.duplex_jobs, 300);
        assert_eq!(deserialized.estimated_savings_cents, 45_000);
    }
}
