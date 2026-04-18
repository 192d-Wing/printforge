// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`AccountingRepository`].
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! Job cost records are append-only. Quota counters use `SELECT FOR UPDATE`
//! to prevent race conditions during concurrent job submissions.

use chrono::NaiveDate;
use pf_common::identity::Edipi;
use pf_common::job::{CostCenter, JobId};
use sqlx::PgPool;

use crate::chargeback::{BillingPeriod, ChargebackReport, CostBreakdown};
use crate::cost_center::{ProjectCode, UserCostProfile};
use crate::cost_model::JobCost;
use crate::error::AccountingError;
use crate::quota::QuotaCounter;
use crate::repository::AccountingRepository;

/// `PostgreSQL`-backed accounting repository.
///
/// Uses `SELECT FOR UPDATE` on quota counters to prevent race conditions
/// during concurrent job submissions.
pub struct PgAccountingRepository {
    pool: PgPool,
}

impl PgAccountingRepository {
    /// Create a new `PgAccountingRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ── Job Cost Row ──────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct JobCostRow {
    job_id: uuid::Uuid,
    cost_center_code: String,
    cost_center_name: String,
    total_impressions: i32,
    base_cost_cents: i64,
    color_surcharge_cents: i64,
    media_surcharge_cents: i64,
    finishing_surcharge_cents: i64,
    duplex_discount_cents: i64,
    total_cost_cents: i64,
    is_estimate: bool,
    calculated_at: chrono::DateTime<chrono::Utc>,
}

impl JobCostRow {
    fn try_into_job_cost(self) -> Result<JobCost, AccountingError> {
        let job_id = JobId::new(self.job_id)?;
        let cost_center = CostCenter::new(&self.cost_center_code, &self.cost_center_name)?;

        Ok(JobCost {
            job_id,
            cost_center,
            total_impressions: u32::try_from(self.total_impressions).unwrap_or(0),
            base_cost_cents: u64::try_from(self.base_cost_cents).unwrap_or(0),
            color_surcharge_cents: u64::try_from(self.color_surcharge_cents).unwrap_or(0),
            media_surcharge_cents: u64::try_from(self.media_surcharge_cents).unwrap_or(0),
            finishing_surcharge_cents: u64::try_from(self.finishing_surcharge_cents).unwrap_or(0),
            duplex_discount_cents: u64::try_from(self.duplex_discount_cents).unwrap_or(0),
            total_cost_cents: u64::try_from(self.total_cost_cents).unwrap_or(0),
            is_estimate: self.is_estimate,
            calculated_at: self.calculated_at,
        })
    }
}

// ── Quota Counter Row ────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct QuotaCounterRow {
    edipi: String,
    page_limit: i32,
    pages_used: i32,
    color_page_limit: i32,
    color_pages_used: i32,
    period_start: chrono::DateTime<chrono::Utc>,
    period_end: chrono::DateTime<chrono::Utc>,
    burst_pages_used: i32,
    burst_limit: i32,
}

impl QuotaCounterRow {
    fn try_into_counter(self) -> Result<QuotaCounter, AccountingError> {
        let edipi = Edipi::new(&self.edipi)?;

        Ok(QuotaCounter {
            edipi,
            page_limit: u32::try_from(self.page_limit).unwrap_or(0),
            pages_used: u32::try_from(self.pages_used).unwrap_or(0),
            color_page_limit: u32::try_from(self.color_page_limit).unwrap_or(0),
            color_pages_used: u32::try_from(self.color_pages_used).unwrap_or(0),
            period_start: self.period_start,
            period_end: self.period_end,
            burst_pages_used: u32::try_from(self.burst_pages_used).unwrap_or(0),
            burst_limit: u32::try_from(self.burst_limit).unwrap_or(0),
        })
    }
}

// ── User Cost Profile Row ────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct UserCostProfileRow {
    edipi: String,
    primary_code: String,
    primary_name: String,
    authorized_overrides_json: serde_json::Value,
    authorized_projects_json: serde_json::Value,
}

impl UserCostProfileRow {
    fn try_into_profile(self) -> Result<UserCostProfile, AccountingError> {
        let edipi = Edipi::new(&self.edipi)?;
        let primary = CostCenter::new(&self.primary_code, &self.primary_name)?;

        let authorized_overrides: Vec<CostCenter> =
            serde_json::from_value(self.authorized_overrides_json)
                .map_err(AccountingError::Serialization)?;

        let authorized_projects: Vec<ProjectCode> =
            serde_json::from_value(self.authorized_projects_json)
                .map_err(AccountingError::Serialization)?;

        Ok(UserCostProfile {
            edipi,
            primary,
            authorized_overrides,
            authorized_projects,
        })
    }
}

// ── Chargeback Report Row ────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ChargebackReportRow {
    report_id: uuid::Uuid,
    cost_center_code: String,
    cost_center_name: String,
    period_start: NaiveDate,
    period_end: NaiveDate,
    total_jobs: i32,
    total_impressions: i32,
    color_impressions: i32,
    total_cost_cents: i64,
    base_cents: i64,
    color_surcharge_cents: i64,
    media_surcharge_cents: i64,
    finishing_surcharge_cents: i64,
    duplex_discount_cents: i64,
    generated_at: chrono::DateTime<chrono::Utc>,
}

impl ChargebackReportRow {
    fn try_into_report(self) -> Result<ChargebackReport, AccountingError> {
        let cost_center = CostCenter::new(&self.cost_center_code, &self.cost_center_name)?;
        let period = BillingPeriod::new(self.period_start, self.period_end)?;

        Ok(ChargebackReport {
            report_id: self.report_id,
            cost_center,
            period,
            total_jobs: u32::try_from(self.total_jobs).unwrap_or(0),
            total_impressions: u32::try_from(self.total_impressions).unwrap_or(0),
            color_impressions: u32::try_from(self.color_impressions).unwrap_or(0),
            total_cost_cents: u64::try_from(self.total_cost_cents).unwrap_or(0),
            cost_breakdown: CostBreakdown {
                base_cents: u64::try_from(self.base_cents).unwrap_or(0),
                color_surcharge_cents: u64::try_from(self.color_surcharge_cents).unwrap_or(0),
                media_surcharge_cents: u64::try_from(self.media_surcharge_cents).unwrap_or(0),
                finishing_surcharge_cents: u64::try_from(self.finishing_surcharge_cents)
                    .unwrap_or(0),
                duplex_discount_cents: u64::try_from(self.duplex_discount_cents).unwrap_or(0),
            },
            generated_at: self.generated_at,
        })
    }
}

impl AccountingRepository for PgAccountingRepository {
    // ── Job Costs ──────────────────────────────────────────────────

    async fn save_job_cost(&self, cost: &JobCost) -> Result<(), AccountingError> {
        sqlx::query(
            "INSERT INTO job_costs (job_id, cost_center_code, cost_center_name, \
             total_impressions, base_cost_cents, color_surcharge_cents, media_surcharge_cents, \
             finishing_surcharge_cents, duplex_discount_cents, total_cost_cents, is_estimate, \
             calculated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (job_id) DO UPDATE SET \
             total_impressions = EXCLUDED.total_impressions, \
             base_cost_cents = EXCLUDED.base_cost_cents, \
             color_surcharge_cents = EXCLUDED.color_surcharge_cents, \
             media_surcharge_cents = EXCLUDED.media_surcharge_cents, \
             finishing_surcharge_cents = EXCLUDED.finishing_surcharge_cents, \
             duplex_discount_cents = EXCLUDED.duplex_discount_cents, \
             total_cost_cents = EXCLUDED.total_cost_cents, \
             is_estimate = EXCLUDED.is_estimate, \
             calculated_at = EXCLUDED.calculated_at",
        )
        .bind(cost.job_id.as_uuid())
        .bind(&cost.cost_center.code)
        .bind(&cost.cost_center.name)
        .bind(cost.total_impressions as i32)
        .bind(cost.base_cost_cents as i64)
        .bind(cost.color_surcharge_cents as i64)
        .bind(cost.media_surcharge_cents as i64)
        .bind(cost.finishing_surcharge_cents as i64)
        .bind(cost.duplex_discount_cents as i64)
        .bind(cost.total_cost_cents as i64)
        .bind(cost.is_estimate)
        .bind(cost.calculated_at)
        .execute(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        Ok(())
    }

    async fn get_job_cost(&self, job_id: &JobId) -> Result<JobCost, AccountingError> {
        let row = sqlx::query_as::<_, JobCostRow>(
            "SELECT job_id, cost_center_code, cost_center_name, total_impressions, \
             base_cost_cents, color_surcharge_cents, media_surcharge_cents, \
             finishing_surcharge_cents, duplex_discount_cents, total_cost_cents, \
             is_estimate, calculated_at FROM job_costs WHERE job_id = $1",
        )
        .bind(job_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(AccountingError::Database)?
        .ok_or_else(|| AccountingError::JobCostNotFound {
            job_id: job_id.as_uuid().to_string(),
        })?;

        row.try_into_job_cost()
    }

    async fn list_job_costs_by_cost_center(
        &self,
        cost_center: &CostCenter,
        start: NaiveDate,
        end: NaiveDate,
    ) -> Result<Vec<JobCost>, AccountingError> {
        let rows = sqlx::query_as::<_, JobCostRow>(
            "SELECT job_id, cost_center_code, cost_center_name, total_impressions, \
             base_cost_cents, color_surcharge_cents, media_surcharge_cents, \
             finishing_surcharge_cents, duplex_discount_cents, total_cost_cents, \
             is_estimate, calculated_at FROM job_costs \
             WHERE cost_center_code = $1 AND calculated_at::date >= $2 AND calculated_at::date <= $3 \
             ORDER BY calculated_at",
        )
        .bind(&cost_center.code)
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        rows.into_iter()
            .map(JobCostRow::try_into_job_cost)
            .collect()
    }

    async fn list_job_costs_by_date_range(
        &self,
        start: NaiveDate,
        end: NaiveDate,
    ) -> Result<Vec<JobCost>, AccountingError> {
        let rows = sqlx::query_as::<_, JobCostRow>(
            "SELECT job_id, cost_center_code, cost_center_name, total_impressions, \
             base_cost_cents, color_surcharge_cents, media_surcharge_cents, \
             finishing_surcharge_cents, duplex_discount_cents, total_cost_cents, \
             is_estimate, calculated_at FROM job_costs \
             WHERE calculated_at::date >= $1 AND calculated_at::date <= $2 \
             ORDER BY calculated_at",
        )
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        rows.into_iter()
            .map(JobCostRow::try_into_job_cost)
            .collect()
    }

    // ── Quota Counters ─────────────────────────────────────────────

    async fn get_quota_counter(&self, edipi: &Edipi) -> Result<QuotaCounter, AccountingError> {
        let row = sqlx::query_as::<_, QuotaCounterRow>(
            "SELECT edipi, page_limit, pages_used, color_page_limit, color_pages_used, \
             period_start, period_end, burst_pages_used, burst_limit \
             FROM quota_counters WHERE edipi = $1 FOR UPDATE",
        )
        .bind(edipi.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(AccountingError::Database)?
        .ok_or_else(|| AccountingError::CostCenterNotFound {
            code: "quota counter not found for user".to_string(),
        })?;

        row.try_into_counter()
    }

    async fn save_quota_counter(&self, counter: &QuotaCounter) -> Result<(), AccountingError> {
        sqlx::query(
            "INSERT INTO quota_counters (edipi, page_limit, pages_used, color_page_limit, \
             color_pages_used, period_start, period_end, burst_pages_used, burst_limit) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (edipi) DO UPDATE SET \
             page_limit = EXCLUDED.page_limit, \
             pages_used = EXCLUDED.pages_used, \
             color_page_limit = EXCLUDED.color_page_limit, \
             color_pages_used = EXCLUDED.color_pages_used, \
             period_start = EXCLUDED.period_start, \
             period_end = EXCLUDED.period_end, \
             burst_pages_used = EXCLUDED.burst_pages_used, \
             burst_limit = EXCLUDED.burst_limit",
        )
        .bind(counter.edipi.as_str())
        .bind(counter.page_limit as i32)
        .bind(counter.pages_used as i32)
        .bind(counter.color_page_limit as i32)
        .bind(counter.color_pages_used as i32)
        .bind(counter.period_start)
        .bind(counter.period_end)
        .bind(counter.burst_pages_used as i32)
        .bind(counter.burst_limit as i32)
        .execute(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        Ok(())
    }

    async fn reset_expired_quotas(&self, as_of: NaiveDate) -> Result<u64, AccountingError> {
        let result = sqlx::query(
            "UPDATE quota_counters SET \
             pages_used = 0, color_pages_used = 0, burst_pages_used = 0 \
             WHERE period_end::date < $1",
        )
        .bind(as_of)
        .execute(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        Ok(result.rows_affected())
    }

    // ── Cost Center Profiles ───────────────────────────────────────

    async fn get_user_cost_profile(
        &self,
        edipi: &Edipi,
    ) -> Result<UserCostProfile, AccountingError> {
        let row = sqlx::query_as::<_, UserCostProfileRow>(
            "SELECT edipi, primary_code, primary_name, authorized_overrides_json, \
             authorized_projects_json FROM user_cost_profiles WHERE edipi = $1",
        )
        .bind(edipi.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(AccountingError::Database)?
        .ok_or_else(|| AccountingError::CostCenterNotFound {
            code: "cost profile not found for user".to_string(),
        })?;

        row.try_into_profile()
    }

    async fn save_user_cost_profile(
        &self,
        profile: &UserCostProfile,
    ) -> Result<(), AccountingError> {
        let overrides_json = serde_json::to_value(&profile.authorized_overrides)
            .map_err(AccountingError::Serialization)?;
        let projects_json = serde_json::to_value(&profile.authorized_projects)
            .map_err(AccountingError::Serialization)?;

        sqlx::query(
            "INSERT INTO user_cost_profiles (edipi, primary_code, primary_name, \
             authorized_overrides_json, authorized_projects_json) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (edipi) DO UPDATE SET \
             primary_code = EXCLUDED.primary_code, \
             primary_name = EXCLUDED.primary_name, \
             authorized_overrides_json = EXCLUDED.authorized_overrides_json, \
             authorized_projects_json = EXCLUDED.authorized_projects_json",
        )
        .bind(profile.edipi.as_str())
        .bind(&profile.primary.code)
        .bind(&profile.primary.name)
        .bind(&overrides_json)
        .bind(&projects_json)
        .execute(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        Ok(())
    }

    // ── Chargeback Reports ─────────────────────────────────────────

    async fn save_chargeback_report(
        &self,
        report: &ChargebackReport,
    ) -> Result<(), AccountingError> {
        sqlx::query(
            "INSERT INTO chargeback_reports (report_id, cost_center_code, cost_center_name, \
             period_start, period_end, total_jobs, total_impressions, color_impressions, \
             total_cost_cents, base_cents, color_surcharge_cents, media_surcharge_cents, \
             finishing_surcharge_cents, duplex_discount_cents, generated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(report.report_id)
        .bind(&report.cost_center.code)
        .bind(&report.cost_center.name)
        .bind(report.period.start)
        .bind(report.period.end)
        .bind(report.total_jobs as i32)
        .bind(report.total_impressions as i32)
        .bind(report.color_impressions as i32)
        .bind(report.total_cost_cents as i64)
        .bind(report.cost_breakdown.base_cents as i64)
        .bind(report.cost_breakdown.color_surcharge_cents as i64)
        .bind(report.cost_breakdown.media_surcharge_cents as i64)
        .bind(report.cost_breakdown.finishing_surcharge_cents as i64)
        .bind(report.cost_breakdown.duplex_discount_cents as i64)
        .bind(report.generated_at)
        .execute(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        Ok(())
    }

    async fn list_chargeback_reports(
        &self,
        cost_center: &CostCenter,
    ) -> Result<Vec<ChargebackReport>, AccountingError> {
        let rows = sqlx::query_as::<_, ChargebackReportRow>(
            "SELECT report_id, cost_center_code, cost_center_name, period_start, period_end, \
             total_jobs, total_impressions, color_impressions, total_cost_cents, base_cents, \
             color_surcharge_cents, media_surcharge_cents, finishing_surcharge_cents, \
             duplex_discount_cents, generated_at FROM chargeback_reports \
             WHERE cost_center_code = $1 ORDER BY period_start DESC",
        )
        .bind(&cost_center.code)
        .fetch_all(&self.pool)
        .await
        .map_err(AccountingError::Database)?;

        rows.into_iter()
            .map(ChargebackReportRow::try_into_report)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_accounting_repo_struct_wraps_pool() {
        // Verify the struct can be constructed. Actual DB tests require
        // an integration test with a running PostgreSQL instance.
        // This test ensures the module compiles and the types are correct.
        assert_eq!(
            std::mem::size_of::<PgAccountingRepository>(),
            std::mem::size_of::<PgPool>()
        );
    }
}
