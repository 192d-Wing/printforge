// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default implementation of [`AccountingService`].
//!
//! Delegates data access to an [`AccountingRepository`] and applies
//! business logic for quota status calculation and chargeback aggregation.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
//! All service operations emit structured tracing events for audit.

use chrono::NaiveDate;
use pf_common::identity::Edipi;
use pf_common::job::CostCenter;
use tracing::info;

use crate::chargeback::{
    BillingPeriod, ChargebackEntry, ChargebackReport, ChargebackReportBuilder, MonthlyTotals,
};
use crate::error::AccountingError;
use crate::repository::AccountingRepository;
use crate::service::{AccountingService, QuotaStatusResponse};

/// Default [`AccountingService`] backed by an [`AccountingRepository`].
///
/// Constructed with a repository implementation; all data access flows
/// through the repository trait.
#[derive(Debug, Clone)]
pub struct AccountingServiceImpl<R> {
    repo: R,
}

impl<R> AccountingServiceImpl<R>
where
    R: AccountingRepository,
{
    /// Create a new service instance with the given repository.
    pub fn new(repo: R) -> Self {
        Self { repo }
    }
}

impl<R> AccountingService for AccountingServiceImpl<R>
where
    R: AccountingRepository + 'static,
{
    /// Fetch the quota counter for the given user and convert it into a
    /// [`QuotaStatusResponse`] with pre-calculated remaining values.
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    fn get_quota_status(
        &self,
        edipi: Edipi,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<QuotaStatusResponse, AccountingError>> + Send + '_>> {
        Box::pin(async move {
            let counter = self.repo.get_quota_counter(&edipi).await?;

            info!(
                edipi = %edipi,
                pages_used = counter.pages_used,
                page_limit = counter.page_limit,
                "quota status queried"
            );

            Ok(QuotaStatusResponse {
                edipi: counter.edipi,
                page_limit: counter.page_limit,
                pages_used: counter.pages_used,
                pages_remaining: counter.page_limit.saturating_sub(counter.pages_used),
                color_page_limit: counter.color_page_limit,
                color_pages_used: counter.color_pages_used,
                color_pages_remaining: counter
                    .color_page_limit
                    .saturating_sub(counter.color_pages_used),
                burst_pages_used: counter.burst_pages_used,
                burst_limit: counter.burst_limit,
                burst_pages_remaining: counter.burst_limit.saturating_sub(counter.burst_pages_used),
                period_start: counter.period_start,
                period_end: counter.period_end,
            })
        })
    }

    /// Query job costs from the repository for the given date range,
    /// aggregate them using [`ChargebackReportBuilder`], and return the
    /// completed report.
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    fn get_chargeback_report(
        &self,
        from: NaiveDate,
        to: NaiveDate,
        cost_center_filter: Option<CostCenter>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ChargebackReport, AccountingError>> + Send + '_>> {
        Box::pin(async move {
            let period = BillingPeriod::new(from, to)?;

            let job_costs = match &cost_center_filter {
                Some(cc) => {
                    self.repo
                        .list_job_costs_by_cost_center(cc, from, to)
                        .await?
                }
                None => self.repo.list_job_costs_by_date_range(from, to).await?,
            };

            // Use the cost center from the filter, or a synthetic "ALL" center
            // when aggregating across all cost centers.
            let report_cost_center = cost_center_filter.unwrap_or_else(|| {
                // Safe: "ALL" and "All Cost Centers" are valid strings.
                CostCenter::new("ALL", "All Cost Centers")
                    .expect("static cost center values are valid")
            });

            let mut builder = ChargebackReportBuilder::new(report_cost_center, period)?;

            for jc in &job_costs {
                builder.add_job(&ChargebackEntry {
                    impressions: jc.total_impressions,
                    color_impressions: if jc.color_surcharge_cents > 0 {
                        jc.total_impressions
                    } else {
                        0
                    },
                    base_cents: jc.base_cost_cents,
                    color_surcharge_cents: jc.color_surcharge_cents,
                    media_surcharge_cents: jc.media_surcharge_cents,
                    finishing_surcharge_cents: jc.finishing_surcharge_cents,
                    duplex_discount_cents: jc.duplex_discount_cents,
                });
            }

            let report = builder.build();

            info!(
                report_id = %report.report_id,
                total_jobs = report.total_jobs,
                total_cost_cents = report.total_cost_cents,
                from = %from,
                to = %to,
                "chargeback report generated"
            );

            Ok(report)
        })
    }

    fn monthly_totals(
        &self,
        installations: Vec<String>,
        start: NaiveDate,
        end: NaiveDate,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MonthlyTotals, AccountingError>> + Send + '_>> {
        Box::pin(async move {
            self.repo.monthly_totals(&installations, start, end).await
        })
    }

    fn get_quota_status_bulk(
        &self,
        edipis: Vec<Edipi>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        std::collections::HashMap<Edipi, QuotaStatusResponse>,
                        AccountingError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let counters = self.repo.get_quota_counters_bulk(&edipis).await?;
            let mut out = std::collections::HashMap::with_capacity(counters.len());
            for (edipi, counter) in counters {
                out.insert(
                    edipi,
                    QuotaStatusResponse {
                        edipi: counter.edipi.clone(),
                        page_limit: counter.page_limit,
                        pages_used: counter.pages_used,
                        pages_remaining: counter
                            .page_limit
                            .saturating_sub(counter.pages_used),
                        color_page_limit: counter.color_page_limit,
                        color_pages_used: counter.color_pages_used,
                        color_pages_remaining: counter
                            .color_page_limit
                            .saturating_sub(counter.color_pages_used),
                        burst_pages_used: counter.burst_pages_used,
                        burst_limit: counter.burst_limit,
                        burst_pages_remaining: counter
                            .burst_limit
                            .saturating_sub(counter.burst_pages_used),
                        period_start: counter.period_start,
                        period_end: counter.period_end,
                    },
                );
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use pf_common::identity::Edipi;
    use pf_common::job::{CostCenter, JobId};

    use super::*;
    use crate::cost_model::JobCost;
    use crate::quota::QuotaCounter;
    use crate::repository::AccountingRepository;

    // ── In-memory mock repository ─────────────────────────────────

    /// A minimal in-memory repository for testing the service layer.
    #[derive(Debug, Default, Clone)]
    struct MockRepo {
        quota_counters: Vec<QuotaCounter>,
        job_costs: Vec<JobCost>,
    }

    impl AccountingRepository for MockRepo {
        async fn save_job_cost(&self, _cost: &JobCost) -> Result<(), AccountingError> {
            Ok(())
        }

        async fn get_job_cost(&self, job_id: &JobId) -> Result<JobCost, AccountingError> {
            self.job_costs
                .iter()
                .find(|jc| jc.job_id == *job_id)
                .cloned()
                .ok_or_else(|| AccountingError::JobCostNotFound {
                    job_id: job_id.as_uuid().to_string(),
                })
        }

        async fn list_job_costs_by_cost_center(
            &self,
            cost_center: &CostCenter,
            start: NaiveDate,
            end: NaiveDate,
        ) -> Result<Vec<JobCost>, AccountingError> {
            Ok(self
                .job_costs
                .iter()
                .filter(|jc| {
                    jc.cost_center.code == cost_center.code
                        && jc.calculated_at.date_naive() >= start
                        && jc.calculated_at.date_naive() <= end
                })
                .cloned()
                .collect())
        }

        async fn list_job_costs_by_date_range(
            &self,
            start: NaiveDate,
            end: NaiveDate,
        ) -> Result<Vec<JobCost>, AccountingError> {
            Ok(self
                .job_costs
                .iter()
                .filter(|jc| {
                    jc.calculated_at.date_naive() >= start
                        && jc.calculated_at.date_naive() <= end
                })
                .cloned()
                .collect())
        }

        async fn get_quota_counter(
            &self,
            edipi: &Edipi,
        ) -> Result<QuotaCounter, AccountingError> {
            self.quota_counters
                .iter()
                .find(|qc| qc.edipi == *edipi)
                .cloned()
                .ok_or_else(|| AccountingError::Database(sqlx::Error::RowNotFound))
        }

        async fn get_quota_counters_bulk(
            &self,
            edipis: &[Edipi],
        ) -> Result<std::collections::HashMap<Edipi, QuotaCounter>, AccountingError> {
            let mut out = std::collections::HashMap::new();
            for edipi in edipis {
                if let Some(qc) = self.quota_counters.iter().find(|qc| qc.edipi == *edipi) {
                    out.insert(edipi.clone(), qc.clone());
                }
            }
            Ok(out)
        }

        async fn save_quota_counter(
            &self,
            _counter: &QuotaCounter,
        ) -> Result<(), AccountingError> {
            Ok(())
        }

        async fn reset_expired_quotas(&self, _as_of: NaiveDate) -> Result<u64, AccountingError> {
            Ok(0)
        }

        async fn get_user_cost_profile(
            &self,
            edipi: &Edipi,
        ) -> Result<crate::cost_center::UserCostProfile, AccountingError> {
            Err(AccountingError::CostCenterNotFound {
                code: edipi.to_string(),
            })
        }

        async fn save_user_cost_profile(
            &self,
            _profile: &crate::cost_center::UserCostProfile,
        ) -> Result<(), AccountingError> {
            Ok(())
        }

        async fn save_chargeback_report(
            &self,
            _report: &ChargebackReport,
        ) -> Result<(), AccountingError> {
            Ok(())
        }

        async fn list_chargeback_reports(
            &self,
            _cost_center: &CostCenter,
        ) -> Result<Vec<ChargebackReport>, AccountingError> {
            Ok(vec![])
        }

        async fn monthly_totals(
            &self,
            _installations: &[String],
            start: NaiveDate,
            end: NaiveDate,
        ) -> Result<MonthlyTotals, AccountingError> {
            // The mock ignores the `installations` filter — it has no
            // user directory to resolve owner -> site. Tests that care
            // about scope enforcement live against the real pg_repo.
            let mut pages: u64 = 0;
            let mut cost_cents: u64 = 0;
            for jc in &self.job_costs {
                let d = jc.calculated_at.date_naive();
                if d >= start && d <= end && !jc.is_estimate {
                    pages = pages.saturating_add(u64::from(jc.total_impressions));
                    cost_cents = cost_cents.saturating_add(jc.total_cost_cents);
                }
            }
            Ok(MonthlyTotals { pages, cost_cents })
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    fn test_edipi() -> Edipi {
        Edipi::new("1234567890").unwrap()
    }

    fn test_cost_center() -> CostCenter {
        CostCenter::new("CC-100", "Test Unit").unwrap()
    }

    fn test_quota_counter() -> QuotaCounter {
        QuotaCounter {
            edipi: test_edipi(),
            page_limit: 500,
            pages_used: 120,
            color_page_limit: 100,
            color_pages_used: 30,
            period_start: Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap(),
            period_end: Utc.with_ymd_and_hms(2026, 3, 31, 23, 59, 59).unwrap(),
            burst_pages_used: 0,
            burst_limit: 50,
        }
    }

    fn test_job_cost(cost_center: &CostCenter, calculated_at: chrono::DateTime<Utc>) -> JobCost {
        JobCost {
            job_id: JobId::generate(),
            cost_center: cost_center.clone(),
            total_impressions: 20,
            base_cost_cents: 60,
            color_surcharge_cents: 0,
            media_surcharge_cents: 0,
            finishing_surcharge_cents: 0,
            duplex_discount_cents: 0,
            total_cost_cents: 60,
            is_estimate: false,
            calculated_at,
        }
    }

    fn test_color_job_cost(
        cost_center: &CostCenter,
        calculated_at: chrono::DateTime<Utc>,
    ) -> JobCost {
        JobCost {
            job_id: JobId::generate(),
            cost_center: cost_center.clone(),
            total_impressions: 10,
            base_cost_cents: 30,
            color_surcharge_cents: 120,
            media_surcharge_cents: 0,
            finishing_surcharge_cents: 0,
            duplex_discount_cents: 0,
            total_cost_cents: 150,
            is_estimate: false,
            calculated_at,
        }
    }

    // ── Quota status tests ────────────────────────────────────────

    #[tokio::test]
    async fn get_quota_status_returns_remaining_pages() {
        let repo = MockRepo {
            quota_counters: vec![test_quota_counter()],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let status = svc.get_quota_status(test_edipi()).await.unwrap();

        assert_eq!(status.page_limit, 500);
        assert_eq!(status.pages_used, 120);
        assert_eq!(status.pages_remaining, 380);
        assert_eq!(status.color_page_limit, 100);
        assert_eq!(status.color_pages_used, 30);
        assert_eq!(status.color_pages_remaining, 70);
        assert_eq!(status.burst_limit, 50);
        assert_eq!(status.burst_pages_used, 0);
        assert_eq!(status.burst_pages_remaining, 50);
    }

    #[tokio::test]
    async fn get_quota_status_saturates_when_over_limit() {
        let mut counter = test_quota_counter();
        counter.pages_used = 500;
        counter.burst_pages_used = 10;

        let repo = MockRepo {
            quota_counters: vec![counter],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let status = svc.get_quota_status(test_edipi()).await.unwrap();

        assert_eq!(status.pages_remaining, 0);
        assert_eq!(status.burst_pages_remaining, 40);
    }

    #[tokio::test]
    async fn get_quota_status_unknown_user_returns_error() {
        let repo = MockRepo::default();
        let svc = AccountingServiceImpl::new(repo);

        let unknown = Edipi::new("9999999999").unwrap();
        let result = svc.get_quota_status(unknown).await;

        assert!(result.is_err());
    }

    // ── Chargeback report tests ───────────────────────────────────

    #[tokio::test]
    async fn get_chargeback_report_with_cost_center_filter() {
        let cc = test_cost_center();
        let ts = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();

        let repo = MockRepo {
            job_costs: vec![
                test_job_cost(&cc, ts),
                test_color_job_cost(&cc, ts),
            ],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let from = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();

        let report = svc
            .get_chargeback_report(from, to, Some(cc.clone()))
            .await
            .unwrap();

        assert_eq!(report.total_jobs, 2);
        assert_eq!(report.cost_breakdown.base_cents, 90); // 60 + 30
        assert_eq!(report.cost_breakdown.color_surcharge_cents, 120);
        assert_eq!(report.total_cost_cents, 210); // 90 + 120
        assert_eq!(report.cost_center.code, "CC-100");
    }

    #[tokio::test]
    async fn get_chargeback_report_without_filter_aggregates_all() {
        let cc1 = test_cost_center();
        let cc2 = CostCenter::new("CC-200", "Other Unit").unwrap();
        let ts = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();

        let repo = MockRepo {
            job_costs: vec![
                test_job_cost(&cc1, ts),
                test_job_cost(&cc2, ts),
            ],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let from = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();

        let report = svc.get_chargeback_report(from, to, None).await.unwrap();

        assert_eq!(report.total_jobs, 2);
        assert_eq!(report.total_cost_cents, 120); // 60 + 60
        assert_eq!(report.cost_center.code, "ALL");
    }

    #[tokio::test]
    async fn get_chargeback_report_empty_period() {
        let repo = MockRepo::default();
        let svc = AccountingServiceImpl::new(repo);

        let from = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();
        let cc = test_cost_center();

        let report = svc
            .get_chargeback_report(from, to, Some(cc.clone()))
            .await
            .unwrap();

        assert_eq!(report.total_jobs, 0);
        assert_eq!(report.total_cost_cents, 0);
    }

    #[tokio::test]
    async fn get_chargeback_report_invalid_period_returns_error() {
        let repo = MockRepo::default();
        let svc = AccountingServiceImpl::new(repo);

        let from = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();

        let result = svc.get_chargeback_report(from, to, None).await;

        assert!(matches!(
            result,
            Err(AccountingError::InvalidChargebackPeriod { .. })
        ));
    }

    #[tokio::test]
    async fn get_chargeback_report_excludes_out_of_range_jobs() {
        let cc = test_cost_center();
        let in_range = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();
        let out_of_range = Utc.with_ymd_and_hms(2026, 4, 15, 10, 0, 0).unwrap();

        let repo = MockRepo {
            job_costs: vec![
                test_job_cost(&cc, in_range),
                test_job_cost(&cc, out_of_range),
            ],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let from = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();

        let report = svc
            .get_chargeback_report(from, to, Some(cc.clone()))
            .await
            .unwrap();

        // Mock filters by date, so only the in-range job should appear.
        assert_eq!(report.total_jobs, 1);
        assert_eq!(report.total_cost_cents, 60);
    }

    // ── NIST compliance evidence tests ────────────────────────────

    #[tokio::test]
    async fn monthly_totals_sums_final_costs_in_range() {
        let cc = test_cost_center();
        let in_range = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();
        let out_of_range = Utc.with_ymd_and_hms(2026, 4, 15, 10, 0, 0).unwrap();

        let repo = MockRepo {
            job_costs: vec![
                test_job_cost(&cc, in_range),
                test_color_job_cost(&cc, in_range),
                test_job_cost(&cc, out_of_range),
            ],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let start = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let end = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();

        let totals = svc.monthly_totals(Vec::new(), start, end).await.unwrap();

        // Two in-range jobs: 20 + 10 impressions = 30; 60 + 150 cents = 210.
        assert_eq!(totals.pages, 30);
        assert_eq!(totals.cost_cents, 210);
    }

    #[tokio::test]
    async fn monthly_totals_excludes_estimates() {
        let cc = test_cost_center();
        let ts = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();
        let mut estimate = test_job_cost(&cc, ts);
        estimate.is_estimate = true;

        let repo = MockRepo {
            job_costs: vec![estimate],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let start = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let end = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();

        let totals = svc.monthly_totals(Vec::new(), start, end).await.unwrap();

        assert_eq!(totals.pages, 0);
        assert_eq!(totals.cost_cents, 0);
    }

    #[tokio::test]
    async fn nist_au12_quota_status_query_succeeds() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        // Evidence: quota status query returns structured data suitable
        // for audit logging (edipi, usage, limits).
        let repo = MockRepo {
            quota_counters: vec![test_quota_counter()],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let status = svc.get_quota_status(test_edipi()).await.unwrap();

        // The response contains all fields needed for an audit record.
        assert_eq!(status.edipi, test_edipi());
        assert!(status.page_limit > 0);
    }

    #[tokio::test]
    async fn nist_au12_chargeback_report_generation_auditable() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        // Evidence: chargeback report generation produces a report with
        // a unique ID and timestamp, suitable for audit trail.
        let cc = test_cost_center();
        let ts = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();

        let repo = MockRepo {
            job_costs: vec![test_job_cost(&cc, ts)],
            ..MockRepo::default()
        };
        let svc = AccountingServiceImpl::new(repo);

        let from = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        let to = NaiveDate::from_ymd_opt(2026, 3, 31).unwrap();

        let report = svc
            .get_chargeback_report(from, to, Some(cc.clone()))
            .await
            .unwrap();

        // Report has a unique ID and generation timestamp for audit.
        assert!(!report.report_id.is_nil());
        assert!(report.generated_at <= Utc::now());
    }
}
