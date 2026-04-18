// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Gateway-owned report generator used by the background worker.
//!
//! The generator is a [`GeneratorFn`](pf_reports::GeneratorFn) closure that
//! dispatches on [`ReportKind`](pf_reports::ReportKind) and calls into the
//! appropriate domain service to produce a report. On kinds that are wired,
//! the generator also serializes the result to CSV and uploads to object
//! storage via [`ReportUploader`] when one is configured; otherwise
//! `output_location` stays `None` and the row count alone is reported.
//!
//! Unimplemented kinds return `Err(reason)` so the worker records the
//! failure via `mark_failed` with a clear diagnostic shown in the admin UI.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation

use std::fmt::Write;
use std::sync::Arc;

use aws_sdk_s3::primitives::ByteStream;
use pf_accounting::{AccountingService, ChargebackReport};
use pf_reports::{GenerationOutcome, GeneratorFn, ReportFormat, ReportKind, ReportRecord};

/// Handle for uploading report artifacts to object storage.
///
/// Constructed at startup from [`ReportsConfig`](crate::config::ReportsConfig);
/// when the configured bucket is empty the gateway never builds one, and the
/// generator simply skips the upload step.
pub struct ReportUploader {
    /// S3 client wired to the configured region + optional endpoint override.
    pub client: aws_sdk_s3::Client,
    /// Destination bucket.
    pub bucket: String,
}

/// Build a [`GeneratorFn`] closure wired to the given domain services and
/// an optional artifact uploader.
///
/// Generators that can serialize to CSV/JSON will upload when `uploader`
/// is `Some` and return the `s3://bucket/key` URI in `output_location`.
/// When `uploader` is `None`, the generator still runs and row counts are
/// accurate — the admin UI just won't surface a download link.
#[must_use]
pub fn build_report_generator(
    accounting: Arc<dyn AccountingService>,
    uploader: Option<Arc<ReportUploader>>,
) -> GeneratorFn {
    Arc::new(move |record| {
        let accounting = accounting.clone();
        let uploader = uploader.clone();
        Box::pin(async move {
            match record.kind {
                ReportKind::Chargeback => {
                    let report = accounting
                        .get_chargeback_report(record.start_date, record.end_date, None)
                        .await
                        .map_err(|e| format!("chargeback query failed: {e}"))?;
                    let row_count = u64::from(report.total_jobs);
                    let output_location =
                        maybe_upload_chargeback(&record, &report, uploader.as_deref()).await?;
                    Ok(GenerationOutcome {
                        row_count,
                        output_location,
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

/// Serialize a chargeback report to the record's requested format and
/// upload it to object storage. Returns the `s3://bucket/key` URI on
/// success. Returns `Ok(None)` when no uploader is configured — upload is
/// optional.
async fn maybe_upload_chargeback(
    record: &ReportRecord,
    report: &ChargebackReport,
    uploader: Option<&ReportUploader>,
) -> Result<Option<String>, String> {
    let Some(uploader) = uploader else {
        return Ok(None);
    };

    let (body, extension, content_type) = match record.format {
        ReportFormat::Csv => (
            serialize_chargeback_csv(report),
            "csv",
            "text/csv",
        ),
        ReportFormat::Json => (
            serde_json::to_string(report)
                .map_err(|e| format!("chargeback JSON serialization failed: {e}"))?,
            "json",
            "application/json",
        ),
    };
    let key = format!("reports/{}.{}", record.id, extension);

    uploader
        .client
        .put_object()
        .bucket(&uploader.bucket)
        .key(&key)
        .body(ByteStream::from(body.into_bytes()))
        .content_type(content_type)
        .send()
        .await
        .map_err(|e| format!("S3 upload to s3://{}/{key} failed: {e}", uploader.bucket))?;

    Ok(Some(format!("s3://{}/{key}", uploader.bucket)))
}

/// Serialize a [`ChargebackReport`] as a single-row CSV summary.
///
/// Intentionally compact — a richer per-job CSV requires per-line items
/// which `ChargebackReport` does not carry today. The SPA renders this
/// as a single summary download until per-job line items are added to
/// the accounting path.
fn serialize_chargeback_csv(report: &ChargebackReport) -> String {
    let mut out = String::new();
    out.push_str(
        "report_id,cost_center_code,cost_center_name,period_start,period_end,\
         total_jobs,total_impressions,color_impressions,total_cost_cents,\
         base_cents,color_surcharge_cents,media_surcharge_cents,\
         finishing_surcharge_cents,duplex_discount_cents\n",
    );
    let _ = writeln!(
        out,
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        report.report_id,
        csv_escape(&report.cost_center.code),
        csv_escape(&report.cost_center.name),
        report.period.start,
        report.period.end,
        report.total_jobs,
        report.total_impressions,
        report.color_impressions,
        report.total_cost_cents,
        report.cost_breakdown.base_cents,
        report.cost_breakdown.color_surcharge_cents,
        report.cost_breakdown.media_surcharge_cents,
        report.cost_breakdown.finishing_surcharge_cents,
        report.cost_breakdown.duplex_discount_cents,
    );
    out
}

/// Quote a CSV field when it contains commas, quotes, or newlines.
/// `cost_center.name` is the only field in practice that can carry a
/// comma; the rest are numeric or well-formed codes.
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Utc};
    use pf_accounting::AccountingError;
    use pf_common::identity::Edipi;
    use pf_common::job::CostCenter;
    use pf_reports::{ReportRecord, ReportState};
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
    async fn chargeback_without_uploader_returns_row_count_and_none_location() {
        let generator = build_report_generator(Arc::new(StubAccounting), None);
        let outcome = generator(sample_record(ReportKind::Chargeback))
            .await
            .unwrap();
        assert_eq!(outcome.row_count, 0);
        assert!(outcome.output_location.is_none());
    }

    #[tokio::test]
    async fn unimplemented_kinds_return_err() {
        let generator = build_report_generator(Arc::new(StubAccounting), None);
        for kind in [
            ReportKind::Utilization,
            ReportKind::QuotaCompliance,
            ReportKind::WasteReduction,
        ] {
            let result = generator(sample_record(kind)).await;
            assert!(result.is_err(), "kind {kind:?} should not be implemented");
        }
    }

    #[test]
    fn csv_escape_quotes_comma_and_double_quote() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("has, comma"), "\"has, comma\"");
        assert_eq!(csv_escape("has \"quote\""), "\"has \"\"quote\"\"\"");
        assert_eq!(csv_escape("has\nnewline"), "\"has\nnewline\"");
    }

    #[test]
    fn serialize_chargeback_csv_has_header_and_row() {
        let period = pf_accounting::BillingPeriod::new(
            NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
        )
        .unwrap();
        let cc = CostCenter::new("CC-001", "Test, Unit").unwrap();
        let report = pf_accounting::ChargebackReportBuilder::new(cc, period)
            .unwrap()
            .build();
        let csv = serialize_chargeback_csv(&report);
        assert!(csv.starts_with("report_id,"));
        // Cost center name gets CSV-quoted because of the comma.
        assert!(csv.contains("\"Test, Unit\""));
    }
}
