// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Aggregated dashboard KPIs: online printers, held jobs, monthly pages, costs.
//!
//! All dashboard queries are scoped by the requester's [`DataScope`](crate::scope::DataScope).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::identity::SiteId;

use crate::scope::DataScope;

/// Top-level KPI snapshot for the admin dashboard.
///
/// **NIST 800-53 Rev 5:** AC-3 — All data is scoped to the requester's
/// authorized sites via [`DataScope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardKpis {
    /// Timestamp when these KPIs were computed.
    pub computed_at: DateTime<Utc>,

    /// Total printers visible under the current scope.
    pub total_printers: u64,

    /// Number of printers currently online.
    pub online_printers: u64,

    /// Number of printers in error state.
    pub error_printers: u64,

    /// Number of printers in maintenance state.
    pub maintenance_printers: u64,

    /// Number of jobs currently held (Follow-Me awaiting release).
    pub held_jobs: u64,

    /// Number of jobs actively printing right now.
    pub active_jobs: u64,

    /// Total pages printed in the current calendar month.
    pub monthly_pages: u64,

    /// Total cost (in cents) accrued in the current calendar month.
    pub monthly_cost_cents: u64,

    /// Number of active alerts requiring attention.
    pub active_alerts: u64,
}

/// Request parameters for fetching dashboard KPIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardRequest {
    /// The data scope derived from the requester's roles.
    #[serde(skip)]
    pub scope: Option<DataScope>,

    /// Optional site filter — must be within the requester's scope.
    pub site_id: Option<SiteId>,
}

/// A time-series data point for dashboard trend charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    /// The timestamp for this data point.
    pub timestamp: DateTime<Utc>,

    /// The value at this point in time.
    pub value: f64,
}

/// Trend data for the dashboard charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardTrends {
    /// Pages-per-day trend.
    pub pages_per_day: Vec<TrendDataPoint>,

    /// Cost-per-day trend (in cents).
    pub cost_per_day: Vec<TrendDataPoint>,

    /// Printer uptime percentage per day.
    pub uptime_per_day: Vec<TrendDataPoint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_kpis_serialization_roundtrip() {
        let kpis = DashboardKpis {
            computed_at: Utc::now(),
            total_printers: 42,
            online_printers: 38,
            error_printers: 2,
            maintenance_printers: 2,
            held_jobs: 15,
            active_jobs: 3,
            monthly_pages: 10_000,
            monthly_cost_cents: 25_000,
            active_alerts: 5,
        };
        let json = serde_json::to_string(&kpis).unwrap();
        let deserialized: DashboardKpis = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_printers, 42);
        assert_eq!(deserialized.online_printers, 38);
    }

    #[test]
    fn trend_data_point_serialization() {
        let point = TrendDataPoint {
            timestamp: Utc::now(),
            value: 123.45,
        };
        let json = serde_json::to_string(&point).unwrap();
        let deserialized: TrendDataPoint = serde_json::from_str(&json).unwrap();
        assert!((deserialized.value - 123.45).abs() < f64::EPSILON);
    }
}
