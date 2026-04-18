// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Gateway-owned report generator used by the background worker.
//!
//! The generator is a [`GeneratorFn`](pf_reports::GeneratorFn) closure that
//! dispatches on [`ReportKind`](pf_reports::ReportKind) and calls into the
//! appropriate domain service to produce a report's row count. Artifact
//! writing (S3 / `RustFS`) is intentionally NOT implemented here yet — the
//! worker sets `output_location = None` and logs a TODO; a follow-up slice
//! will wire up aws-sdk-s3.
//!
//! Unimplemented kinds return `Err(reason)` so the worker records the
//! failure via `mark_failed` with a clear diagnostic shown in the admin UI.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation

use std::sync::Arc;

use pf_accounting::AccountingService;
use pf_reports::{GenerationOutcome, GeneratorFn, ReportKind};

/// Build a [`GeneratorFn`] closure wired to the given domain services.
///
/// The returned closure captures `Arc` handles so the worker task can hold
/// it for the lifetime of the process.
#[must_use]
pub fn build_report_generator(accounting: Arc<dyn AccountingService>) -> GeneratorFn {
    Arc::new(move |record| {
        let accounting = accounting.clone();
        Box::pin(async move {
            match record.kind {
                ReportKind::Chargeback => {
                    let report = accounting
                        .get_chargeback_report(record.start_date, record.end_date, None)
                        .await
                        .map_err(|e| format!("chargeback query failed: {e}"))?;
                    // TODO(reports-s3): serialize + upload to object storage
                    // and return the path in output_location.
                    Ok(GenerationOutcome {
                        row_count: u64::from(report.total_jobs),
                        output_location: None,
                    })
                }
                ReportKind::Utilization => Err(
                    "utilization report generator not implemented yet".to_string(),
                ),
                ReportKind::QuotaCompliance => Err(
                    "quota compliance report generator not implemented yet".to_string(),
                ),
                ReportKind::WasteReduction => Err(
                    "waste reduction report generator not implemented yet".to_string(),
                ),
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Utc};
    use pf_accounting::AccountingError;
    use pf_common::identity::Edipi;
    use pf_common::job::CostCenter;
    use pf_reports::{ReportFormat, ReportRecord, ReportState};
    use std::future::Future;
    use std::pin::Pin;
    use uuid::Uuid;

    struct StubAccounting;

    impl pf_accounting::AccountingService for StubAccounting {
        fn get_quota_status(
            &self,
            _edipi: Edipi,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<pf_accounting::QuotaStatusResponse, AccountingError>,
                    > + Send
                    + '_,
            >,
        > {
            unreachable!("generator should not call get_quota_status")
        }

        fn get_chargeback_report(
            &self,
            from: NaiveDate,
            to: NaiveDate,
            _cost_center_filter: Option<CostCenter>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<pf_accounting::ChargebackReport, AccountingError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let period = pf_accounting::BillingPeriod::new(from, to).unwrap();
                let cc = CostCenter::new("ALL", "All Cost Centers").unwrap();
                let builder = pf_accounting::ChargebackReportBuilder::new(cc, period).unwrap();
                // Report the stub returns has 0 jobs; worker uses total_jobs
                // as row_count.
                Ok(builder.build())
            })
        }

        fn monthly_totals(
            &self,
            _installations: Vec<String>,
            _start: NaiveDate,
            _end: NaiveDate,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<pf_accounting::MonthlyTotals, AccountingError>>
                    + Send
                    + '_,
            >,
        > {
            unreachable!("generator should not call monthly_totals")
        }

        fn get_quota_status_bulk(
            &self,
            _edipis: Vec<Edipi>,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            std::collections::HashMap<Edipi, pf_accounting::QuotaStatusResponse>,
                            AccountingError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            unreachable!("generator should not call get_quota_status_bulk")
        }
    }

    fn sample_record(kind: ReportKind) -> ReportRecord {
        ReportRecord {
            id: Uuid::now_v7(),
            kind,
            format: ReportFormat::Csv,
            requested_by: "1234567890".to_string(),
            requested_at: Utc::now(),
            site_id: String::new(),
            start_date: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
            state: ReportState::Generating,
            row_count: None,
            output_location: None,
            failure_reason: None,
            completed_at: None,
        }
    }

    #[tokio::test]
    async fn chargeback_generator_delegates_to_accounting() {
        let generator = build_report_generator(Arc::new(StubAccounting));
        let outcome = generator(sample_record(ReportKind::Chargeback)).await.unwrap();
        // Empty chargeback from the stub ⇒ row_count == 0.
        assert_eq!(outcome.row_count, 0);
        assert!(outcome.output_location.is_none());
    }

    #[tokio::test]
    async fn unimplemented_kinds_return_err() {
        let generator = build_report_generator(Arc::new(StubAccounting));
        for kind in [
            ReportKind::Utilization,
            ReportKind::QuotaCompliance,
            ReportKind::WasteReduction,
        ] {
            let result = generator(sample_record(kind)).await;
            assert!(result.is_err(), "kind {kind:?} should not be implemented");
        }
    }
}
