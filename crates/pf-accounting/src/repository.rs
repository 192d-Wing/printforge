// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for job costs, quota counters, and cost center mappings.
//!
//! Defines the data access interface consumed by the accounting service.
//! Implementations use `PostgreSQL` with `SELECT FOR UPDATE` on quota counters
//! to prevent race conditions during concurrent job submissions.
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! Financial records are append-only; no UPDATE/DELETE on cost records.

use std::future::Future;

use chrono::NaiveDate;
use pf_common::identity::Edipi;
use pf_common::job::{CostCenter, JobId};

use crate::chargeback::{ChargebackReport, MonthlyTotals};
use crate::cost_center::UserCostProfile;
use crate::cost_model::JobCost;
use crate::error::AccountingError;
use crate::quota::QuotaCounter;

/// Repository interface for accounting data access.
///
/// All methods return [`AccountingError`] on failure. Implementations
/// should use transactions with `SELECT FOR UPDATE` on quota counters
/// to prevent race conditions.
pub trait AccountingRepository: Send + Sync {
    // ── Job Costs ──────────────────────────────────────────────────

    /// Store a job cost record (estimated or final).
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn save_job_cost(
        &self,
        cost: &JobCost,
    ) -> impl Future<Output = Result<(), AccountingError>> + Send;

    /// Retrieve the cost record for a given job.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::JobCostNotFound`] if no record exists,
    /// or [`AccountingError::Database`] on persistence failure.
    fn get_job_cost(
        &self,
        job_id: &JobId,
    ) -> impl Future<Output = Result<JobCost, AccountingError>> + Send;

    /// List all job costs for a cost center within a date range.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn list_job_costs_by_cost_center(
        &self,
        cost_center: &CostCenter,
        start: NaiveDate,
        end: NaiveDate,
    ) -> impl Future<Output = Result<Vec<JobCost>, AccountingError>> + Send;

    // ── Quota Counters ─────────────────────────────────────────────

    /// Retrieve the current quota counter for a user, locking the row
    /// for update to prevent race conditions.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn get_quota_counter(
        &self,
        edipi: &Edipi,
    ) -> impl Future<Output = Result<QuotaCounter, AccountingError>> + Send;

    /// Retrieve quota counters for a batch of users in a single round-trip.
    ///
    /// Users with no counter row are simply absent from the returned map
    /// — the caller decides how to render "no quota set". No row-level
    /// locking; this is a read path, unlike [`Self::get_quota_counter`].
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn get_quota_counters_bulk(
        &self,
        edipis: &[Edipi],
    ) -> impl Future<
        Output = Result<std::collections::HashMap<Edipi, QuotaCounter>, AccountingError>,
    > + Send;

    /// Persist an updated quota counter.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn save_quota_counter(
        &self,
        counter: &QuotaCounter,
    ) -> impl Future<Output = Result<(), AccountingError>> + Send;

    /// Reset all quota counters for users whose period has expired.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn reset_expired_quotas(
        &self,
        as_of: NaiveDate,
    ) -> impl Future<Output = Result<u64, AccountingError>> + Send;

    // ── Cost Center Profiles ───────────────────────────────────────

    /// Retrieve the cost center profile for a user.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::CostCenterNotFound`] if the user has no
    /// profile, or [`AccountingError::Database`] on persistence failure.
    fn get_user_cost_profile(
        &self,
        edipi: &Edipi,
    ) -> impl Future<Output = Result<UserCostProfile, AccountingError>> + Send;

    /// Persist a user's cost center profile.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn save_user_cost_profile(
        &self,
        profile: &UserCostProfile,
    ) -> impl Future<Output = Result<(), AccountingError>> + Send;

    /// List all job costs within a date range across all cost centers.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn list_job_costs_by_date_range(
        &self,
        start: NaiveDate,
        end: NaiveDate,
    ) -> impl Future<Output = Result<Vec<JobCost>, AccountingError>> + Send;

    // ── Chargeback Reports ─────────────────────────────────────────

    /// Store a generated chargeback report.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn save_chargeback_report(
        &self,
        report: &ChargebackReport,
    ) -> impl Future<Output = Result<(), AccountingError>> + Send;

    /// Retrieve chargeback reports for a cost center.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn list_chargeback_reports(
        &self,
        cost_center: &CostCenter,
    ) -> impl Future<Output = Result<Vec<ChargebackReport>, AccountingError>> + Send;

    /// Sum impressions and cost cents over a date range, optionally scoped to
    /// a set of installations via the job owner's `users.site_id`. An empty
    /// `installations` slice means "no site filter".
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::Database`] on persistence failure.
    fn monthly_totals(
        &self,
        installations: &[String],
        start: NaiveDate,
        end: NaiveDate,
    ) -> impl Future<Output = Result<MonthlyTotals, AccountingError>> + Send;
}
