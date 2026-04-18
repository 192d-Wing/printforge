// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `AccountingService` trait defining the high-level accounting operations.
//!
//! This trait provides the public API surface for quota status queries and
//! chargeback report generation. Implementations are expected to delegate
//! data access to an [`AccountingRepository`].
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
//! All service operations produce auditable outcomes (quota queries,
//! chargeback generation).

use std::future::Future;
use std::pin::Pin;

use chrono::NaiveDate;
use pf_common::identity::Edipi;
use pf_common::job::CostCenter;

use crate::chargeback::ChargebackReport;
use crate::error::AccountingError;

/// Response containing a user's current quota status.
///
/// Aggregates the raw [`QuotaCounter`](crate::quota::QuotaCounter) into a
/// presentation-friendly form showing remaining allowances and period info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuotaStatusResponse {
    /// The user's EDIPI.
    pub edipi: Edipi,
    /// Total page limit for the current period.
    pub page_limit: u32,
    /// Pages consumed so far.
    pub pages_used: u32,
    /// Remaining standard pages.
    pub pages_remaining: u32,
    /// Color page limit for the current period.
    pub color_page_limit: u32,
    /// Color pages consumed so far.
    pub color_pages_used: u32,
    /// Remaining color pages.
    pub color_pages_remaining: u32,
    /// Burst pages consumed above the standard limit.
    pub burst_pages_used: u32,
    /// Maximum burst pages allowed.
    pub burst_limit: u32,
    /// Remaining burst pages.
    pub burst_pages_remaining: u32,
    /// Start of the current billing period (UTC).
    pub period_start: chrono::DateTime<chrono::Utc>,
    /// End of the current billing period (UTC).
    pub period_end: chrono::DateTime<chrono::Utc>,
}

/// High-level accounting service trait.
///
/// Implementations orchestrate repository calls and business logic for
/// quota status queries and chargeback report generation.
pub trait AccountingService: Send + Sync {
    /// Retrieve the current quota status for a user identified by EDIPI.
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    /// Quota status queries are logged for audit purposes.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on repository failure.
    fn get_quota_status(
        &self,
        edipi: Edipi,
    ) -> Pin<Box<dyn Future<Output = Result<QuotaStatusResponse, AccountingError>> + Send + '_>>;

    /// Generate a chargeback report for a date range, optionally filtered
    /// by cost center.
    ///
    /// When `cost_center_filter` is `None`, the report covers all cost centers
    /// that had activity in the given period.
    ///
    /// When `cost_center_filter` is `Some`, only costs charged to that cost
    /// center are included.
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    /// Chargeback report generation is an auditable event.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidChargebackPeriod`] if `from > to`.
    /// Returns [`AccountingError::Database`] on repository failure.
    fn get_chargeback_report(
        &self,
        from: NaiveDate,
        to: NaiveDate,
        cost_center_filter: Option<CostCenter>,
    ) -> Pin<Box<dyn Future<Output = Result<ChargebackReport, AccountingError>> + Send + '_>>;
}
