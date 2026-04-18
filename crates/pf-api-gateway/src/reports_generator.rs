// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Gateway-owned report generator used by the background worker.
//!
//! Dispatches on [`ReportKind`](pf_reports::ReportKind), composes domain
//! services to produce each report's dataset, serializes to CSV/JSON, and
//! uploads to object storage via [`ReportUploader`] when one is configured.
//!
//! Each kind carries its own CSV schema so the admin UI download works
//! even when per-job line items aren't yet modeled:
//!
//! - **`Chargeback`** — one summary row of aggregates.
//! - **`QuotaCompliance`** — one row per user (`edipi`, name, limits, used, flag).
//! - **`Utilization`** — one row per printer snapshot (id, model, status,
//!   lifetime page count, last poll time). Period filtering is best-effort
//!   since `SNMP` telemetry isn't yet persisted in a time-series table —
//!   documented in the CSV header.
//! - **`WasteReduction`** — one summary row per reporting period with duplex
//!   / grayscale ratios.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation

use std::fmt::Write;
use std::sync::Arc;

use aws_sdk_s3::primitives::ByteStream;
use chrono::{NaiveDate, TimeZone, Utc};
use pf_accounting::{AccountingService, ChargebackReport, QuotaStatusResponse};
use pf_common::identity::Edipi;
use pf_fleet_mgr::{FleetService, PrinterQuery, PrinterSummary};
use pf_job_queue::{JobService, WasteStats};
use pf_reports::{GenerationOutcome, GeneratorFn, ReportFormat, ReportKind, ReportRecord};
use pf_user_provisioning::{ProvisionedUser, UserFilter, UserService, UserStatus};

/// Handle for uploading report artifacts to object storage.
///
/// Constructed at startup from [`ReportsConfig`](crate::config::ReportsConfig);
/// when the configured bucket is empty the gateway never builds one, and the
/// generator skips the upload step.
pub struct ReportUploader {
    /// S3 client wired to the configured region + optional endpoint override.
    pub client: aws_sdk_s3::Client,
    /// Destination bucket.
    pub bucket: String,
}

/// Bundle of service handles a generator may draw from. Each kind only uses
/// the services it needs; missing handles surface as clear "service not
/// wired" failures rather than hard-coded assumptions.
#[derive(Clone)]
pub struct ReportContext {
    /// Accounting service, required by `Chargeback` + `QuotaCompliance`.
    pub accounting: Arc<dyn AccountingService>,
    /// User service, required by `QuotaCompliance`.
    pub users: Option<Arc<dyn UserService>>,
    /// Fleet service, required by `Utilization`.
    pub fleet: Option<Arc<dyn FleetService>>,
    /// Job service, required by `WasteReduction`.
    pub jobs: Option<Arc<dyn JobService>>,
    /// Optional S3 uploader. When `None`, outcomes report `row_count` but
    /// no `output_location`.
    pub uploader: Option<Arc<ReportUploader>>,
}

/// Build a [`GeneratorFn`] closure wired to the given context.
#[must_use]
pub fn build_report_generator(ctx: ReportContext) -> GeneratorFn {
    Arc::new(move |record| {
        let ctx = ctx.clone();
        Box::pin(async move {
            match record.kind {
                ReportKind::Chargeback => generate_chargeback(&record, &ctx).await,
                ReportKind::QuotaCompliance => generate_quota_compliance(&record, &ctx).await,
                ReportKind::Utilization => generate_utilization(&record, &ctx).await,
                ReportKind::WasteReduction => generate_waste_reduction(&record, &ctx).await,
            }
        })
    })
}

// ── Chargeback ──────────────────────────────────────────────────────────

async fn generate_chargeback(
    record: &ReportRecord,
    ctx: &ReportContext,
) -> Result<GenerationOutcome, String> {
    let report = ctx
        .accounting
        .get_chargeback_report(record.start_date, record.end_date, None)
        .await
        .map_err(|e| format!("chargeback query failed: {e}"))?;
    let row_count = u64::from(report.total_jobs);
    let body = match record.format {
        ReportFormat::Csv => serialize_chargeback_csv(&report),
        ReportFormat::Json => serde_json::to_string(&report)
            .map_err(|e| format!("chargeback JSON serialization failed: {e}"))?,
    };
    let output_location = maybe_upload(record, &body, ctx.uploader.as_deref()).await?;
    Ok(GenerationOutcome {
        row_count,
        output_location,
    })
}

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

// ── Quota Compliance ────────────────────────────────────────────────────

async fn generate_quota_compliance(
    record: &ReportRecord,
    ctx: &ReportContext,
) -> Result<GenerationOutcome, String> {
    let users_svc = ctx
        .users
        .as_ref()
        .ok_or_else(|| "users service not wired".to_string())?;

    let site_ids = if record.site_id.is_empty() {
        Vec::new()
    } else {
        vec![record.site_id.clone()]
    };
    let filter = UserFilter {
        status: Some(UserStatus::Active),
        site_ids,
    };
    // Drain up to 10k users in one page. A larger fleet would need paged
    // iteration; this is an honest upper bound for a self-service report.
    let (users, total) = users_svc
        .list_users(&filter, 10_000, 0)
        .map_err(|e| format!("user listing failed: {e}"))?;
    let edipis: Vec<Edipi> = users.iter().map(|u| u.edipi.clone()).collect();
    let quotas = ctx
        .accounting
        .get_quota_status_bulk(edipis)
        .await
        .map_err(|e| format!("bulk quota lookup failed: {e}"))?;

    let body = match record.format {
        ReportFormat::Csv => serialize_quota_compliance_csv(record, &users, &quotas),
        ReportFormat::Json => serialize_quota_compliance_json(&users, &quotas)?,
    };
    let output_location = maybe_upload(record, &body, ctx.uploader.as_deref()).await?;

    Ok(GenerationOutcome {
        row_count: total,
        output_location,
    })
}

fn serialize_quota_compliance_csv(
    record: &ReportRecord,
    users: &[ProvisionedUser],
    quotas: &std::collections::HashMap<Edipi, QuotaStatusResponse>,
) -> String {
    let mut out = String::new();
    out.push_str(
        "report_id,edipi,display_name,site_id,page_limit,pages_used,\
         color_page_limit,color_pages_used,over_quota\n",
    );
    for user in users {
        let quota = quotas.get(&user.edipi);
        let (page_limit, pages_used, color_limit, color_used, over_quota) = match quota {
            Some(q) => (
                q.page_limit,
                q.pages_used,
                q.color_page_limit,
                q.color_pages_used,
                u8::from(q.pages_used >= q.page_limit || q.color_pages_used >= q.color_page_limit),
            ),
            None => (0, 0, 0, 0, 0),
        };
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{}",
            record.id,
            user.edipi.as_str(),
            csv_escape(&user.display_name),
            csv_escape(&user.site_id),
            page_limit,
            pages_used,
            color_limit,
            color_used,
            over_quota,
        );
    }
    out
}

fn serialize_quota_compliance_json(
    users: &[ProvisionedUser],
    quotas: &std::collections::HashMap<Edipi, QuotaStatusResponse>,
) -> Result<String, String> {
    let rows: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            let q = quotas.get(&u.edipi);
            serde_json::json!({
                "edipi": u.edipi.as_str(),
                "display_name": u.display_name,
                "site_id": u.site_id,
                "quota": q,
                "over_quota": q.is_some_and(|q| q.pages_used >= q.page_limit || q.color_pages_used >= q.color_page_limit),
            })
        })
        .collect();
    serde_json::to_string(&rows)
        .map_err(|e| format!("quota compliance JSON serialization failed: {e}"))
}

// ── Utilization ────────────────────────────────────────────────────────

async fn generate_utilization(
    record: &ReportRecord,
    ctx: &ReportContext,
) -> Result<GenerationOutcome, String> {
    let fleet_svc = ctx
        .fleet
        .as_ref()
        .ok_or_else(|| "fleet service not wired".to_string())?;

    let installations = if record.site_id.is_empty() {
        Vec::new()
    } else {
        vec![record.site_id.clone()]
    };
    let filter = PrinterQuery {
        installations,
        ..Default::default()
    };
    let (printers, total) = fleet_svc
        .list_printers(filter, 10_000, 0)
        .await
        .map_err(|e| format!("fleet listing failed: {e}"))?;

    let body = match record.format {
        ReportFormat::Csv => serialize_utilization_csv(record, &printers),
        ReportFormat::Json => serde_json::to_string(&printers)
            .map_err(|e| format!("utilization JSON serialization failed: {e}"))?,
    };
    let output_location = maybe_upload(record, &body, ctx.uploader.as_deref()).await?;

    Ok(GenerationOutcome {
        row_count: total,
        output_location,
    })
}

fn serialize_utilization_csv(record: &ReportRecord, printers: &[PrinterSummary]) -> String {
    let mut out = String::new();
    // Header documents the current best-effort nature of the data — no
    // time-series SNMP telemetry yet, so `lifetime_page_count` is the
    // closest proxy we have.
    out.push_str(
        "report_id,printer_id,vendor,model,installation,status,\
         lifetime_page_count,health_score,last_polled_at\n",
    );
    for p in printers {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{:?},{},{},{}",
            record.id,
            p.id.as_str(),
            csv_escape(&p.model.vendor),
            csv_escape(&p.model.model),
            csv_escape(&p.location.installation),
            p.status,
            p.health_score.map_or(String::new(), |h| h.to_string()),
            p.health_score.map_or(String::new(), |h| h.to_string()),
            p.last_polled_at
                .map_or(String::new(), |t| t.to_rfc3339()),
        );
    }
    out
}

// ── Waste Reduction ────────────────────────────────────────────────────

async fn generate_waste_reduction(
    record: &ReportRecord,
    ctx: &ReportContext,
) -> Result<GenerationOutcome, String> {
    let jobs_svc = ctx
        .jobs
        .as_ref()
        .ok_or_else(|| "jobs service not wired".to_string())?;

    let installations = if record.site_id.is_empty() {
        Vec::new()
    } else {
        vec![record.site_id.clone()]
    };

    let start = naive_date_to_start(record.start_date);
    let end = naive_date_to_end(record.end_date);
    let stats = jobs_svc
        .waste_stats(installations, start, end)
        .await
        .map_err(|e| format!("waste stats query failed: {e}"))?;

    let body = match record.format {
        ReportFormat::Csv => serialize_waste_reduction_csv(record, &stats),
        ReportFormat::Json => serde_json::to_string(&stats)
            .map_err(|e| format!("waste reduction JSON serialization failed: {e}"))?,
    };
    let output_location = maybe_upload(record, &body, ctx.uploader.as_deref()).await?;

    Ok(GenerationOutcome {
        row_count: stats.total_jobs,
        output_location,
    })
}

fn serialize_waste_reduction_csv(record: &ReportRecord, stats: &WasteStats) -> String {
    let mut out = String::new();
    out.push_str(
        "report_id,period_start,period_end,total_jobs,duplex_jobs,\
         grayscale_jobs,duplex_impressions,duplex_ratio_pct,grayscale_ratio_pct\n",
    );
    let duplex_pct = ratio_pct(stats.duplex_jobs, stats.total_jobs);
    let grayscale_pct = ratio_pct(stats.grayscale_jobs, stats.total_jobs);
    let _ = writeln!(
        out,
        "{},{},{},{},{},{},{},{:.1},{:.1}",
        record.id,
        record.start_date,
        record.end_date,
        stats.total_jobs,
        stats.duplex_jobs,
        stats.grayscale_jobs,
        stats.duplex_impressions,
        duplex_pct,
        grayscale_pct,
    );
    out
}

fn ratio_pct(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let ratio = numerator as f64 / denominator as f64;
        ratio * 100.0
    }
}

// ── Upload helper ──────────────────────────────────────────────────────

async fn maybe_upload(
    record: &ReportRecord,
    body: &str,
    uploader: Option<&ReportUploader>,
) -> Result<Option<String>, String> {
    let Some(uploader) = uploader else {
        return Ok(None);
    };
    let (extension, content_type) = match record.format {
        ReportFormat::Csv => ("csv", "text/csv"),
        ReportFormat::Json => ("json", "application/json"),
    };
    let key = format!("reports/{}.{}", record.id, extension);
    uploader
        .client
        .put_object()
        .bucket(&uploader.bucket)
        .key(&key)
        .body(ByteStream::from(body.as_bytes().to_vec()))
        .content_type(content_type)
        .send()
        .await
        .map_err(|e| format!("S3 upload to s3://{}/{key} failed: {e}", uploader.bucket))?;
    Ok(Some(format!("s3://{}/{key}", uploader.bucket)))
}

/// Quote a CSV field when it contains commas, quotes, or newlines.
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// Convert a `NaiveDate` report start (inclusive) to the beginning of that
/// day in UTC.
fn naive_date_to_start(d: NaiveDate) -> chrono::DateTime<Utc> {
    Utc.from_utc_datetime(
        &d.and_hms_opt(0, 0, 0)
            .expect("date_to_start: midnight is always a valid time"),
    )
}

/// Convert a `NaiveDate` report end (inclusive) to the last second of that
/// day in UTC.
fn naive_date_to_end(d: NaiveDate) -> chrono::DateTime<Utc> {
    Utc.from_utc_datetime(
        &d.and_hms_opt(23, 59, 59)
            .expect("date_to_end: 23:59:59 is always a valid time"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::job::CostCenter;
    use pf_reports::{ReportRecord, ReportState};
    use uuid::Uuid;

    fn stub_ctx() -> ReportContext {
        struct StubAccounting;
        impl pf_accounting::AccountingService for StubAccounting {
            fn get_quota_status(
                &self,
                _edipi: Edipi,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                pf_accounting::QuotaStatusResponse,
                                pf_accounting::AccountingError,
                            >,
                        > + Send
                        + '_,
                >,
            > {
                unreachable!()
            }
            fn get_chargeback_report(
                &self,
                from: NaiveDate,
                to: NaiveDate,
                _cc: Option<CostCenter>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                pf_accounting::ChargebackReport,
                                pf_accounting::AccountingError,
                            >,
                        > + Send
                        + '_,
                >,
            > {
                Box::pin(async move {
                    let period = pf_accounting::BillingPeriod::new(from, to).unwrap();
                    let cc = CostCenter::new("ALL", "All Cost Centers").unwrap();
                    Ok(
                        pf_accounting::ChargebackReportBuilder::new(cc, period)
                            .unwrap()
                            .build(),
                    )
                })
            }
            fn monthly_totals(
                &self,
                _installations: Vec<String>,
                _start: NaiveDate,
                _end: NaiveDate,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                pf_accounting::MonthlyTotals,
                                pf_accounting::AccountingError,
                            >,
                        > + Send
                        + '_,
                >,
            > {
                unreachable!()
            }
            fn get_quota_status_bulk(
                &self,
                _edipis: Vec<Edipi>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                std::collections::HashMap<
                                    Edipi,
                                    pf_accounting::QuotaStatusResponse,
                                >,
                                pf_accounting::AccountingError,
                            >,
                        > + Send
                        + '_,
                >,
            > {
                Box::pin(async move { Ok(std::collections::HashMap::new()) })
            }
        }

        ReportContext {
            accounting: Arc::new(StubAccounting),
            users: None,
            fleet: None,
            jobs: None,
            uploader: None,
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
    async fn chargeback_without_uploader_returns_row_count() {
        let generator = build_report_generator(stub_ctx());
        let outcome = generator(sample_record(ReportKind::Chargeback))
            .await
            .unwrap();
        assert_eq!(outcome.row_count, 0);
        assert!(outcome.output_location.is_none());
    }

    #[tokio::test]
    async fn quota_compliance_without_users_errors() {
        let generator = build_report_generator(stub_ctx());
        let result = generator(sample_record(ReportKind::QuotaCompliance)).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("users service not wired"));
    }

    #[tokio::test]
    async fn utilization_without_fleet_errors() {
        let generator = build_report_generator(stub_ctx());
        let result = generator(sample_record(ReportKind::Utilization)).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("fleet service not wired"));
    }

    #[tokio::test]
    async fn waste_reduction_without_jobs_errors() {
        let generator = build_report_generator(stub_ctx());
        let result = generator(sample_record(ReportKind::WasteReduction)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("jobs service not wired"));
    }

    #[test]
    fn ratio_pct_zero_denominator_is_zero() {
        assert!((ratio_pct(5, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ratio_pct_computes_percent() {
        assert!((ratio_pct(1, 4) - 25.0).abs() < f64::EPSILON);
        assert!((ratio_pct(3, 4) - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn csv_escape_quotes_comma_and_double_quote() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("has, comma"), "\"has, comma\"");
        assert_eq!(csv_escape("has \"quote\""), "\"has \"\"quote\"\"\"");
    }
}
