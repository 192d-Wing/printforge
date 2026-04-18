// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Background report-generation worker.
//!
//! The worker's job is simple: claim a Pending row, hand it to a caller-
//! supplied generator closure, and then transition the row to `Ready` or
//! `Failed` based on the result. The generator knows how to produce each
//! [`ReportKind`](crate::ReportKind) — this crate does not, so the
//! generator closure is passed in at construction time rather than built
//! into `pf-reports`. That keeps pf-reports free of dependencies on
//! pf-accounting / pf-audit / the concrete report producers.
//!
//! Typical usage from the gateway binary:
//!
//! ```ignore
//! let worker = ReportWorker::new(report_svc, |record| {
//!     Box::pin(async move { generate_for_kind(record).await })
//! });
//! tokio::spawn(async move {
//!     loop {
//!         if let Err(e) = worker.run_one().await {
//!             tracing::warn!(error = %e, "worker tick failed");
//!         }
//!         tokio::time::sleep(std::time::Duration::from_secs(5)).await;
//!     }
//! });
//! ```
//!
//! This scaffolding does not yet schedule itself from `main.rs`; wiring a
//! generator closure that dispatches across accounting/fleet/audit services
//! and writes artifacts to object storage is the next piece of work.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use uuid::Uuid;

use crate::error::ReportError;
use crate::service::ReportService;
use crate::types::ReportRecord;

/// Outcome returned by a generator closure.
#[derive(Debug, Clone)]
pub struct GenerationOutcome {
    /// Total rows in the produced artifact.
    pub row_count: u64,
    /// Object-storage path of the artifact, if any.
    pub output_location: Option<String>,
}

/// A closure that produces an artifact for a claimed [`ReportRecord`].
///
/// On success the closure returns [`GenerationOutcome`]; on failure it
/// returns a short diagnostic string that will be persisted to
/// `reports.failure_reason` and shown in the admin UI.
pub type GeneratorFn = Arc<
    dyn Fn(ReportRecord) -> Pin<Box<dyn Future<Output = Result<GenerationOutcome, String>> + Send>>
        + Send
        + Sync,
>;

/// Background runner that drives `Pending → Generating → Ready | Failed`
/// transitions by calling into a caller-supplied [`GeneratorFn`].
pub struct ReportWorker {
    svc: Arc<dyn ReportService>,
    generator: GeneratorFn,
}

impl ReportWorker {
    /// Create a new worker wrapping `svc` and dispatching generation to
    /// `generator`.
    #[must_use]
    pub fn new(svc: Arc<dyn ReportService>, generator: GeneratorFn) -> Self {
        Self { svc, generator }
    }

    /// Claim a single Pending report, run the generator, and persist the
    /// outcome. Returns the id that was processed, or `None` if no work
    /// was available.
    ///
    /// Errors produced by the generator itself are captured and surfaced
    /// via `mark_failed` — they do not propagate out of this method. Only
    /// persistence failures bubble up as `Err`.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError`] on claim / mark persistence failure.
    pub async fn run_one(&self) -> Result<Option<Uuid>, ReportError> {
        let Some(record) = self.svc.claim_next_pending().await? else {
            return Ok(None);
        };
        let id = record.id;

        match (self.generator)(record).await {
            Ok(outcome) => {
                self.svc
                    .mark_ready(id, outcome.row_count, outcome.output_location)
                    .await?;
            }
            Err(reason) => {
                self.svc.mark_failed(id, reason).await?;
            }
        }

        Ok(Some(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryReportRepository;
    use crate::service_impl::ReportServiceImpl;
    use crate::types::{NewReport, ReportFormat, ReportKind, ReportState};
    use chrono::NaiveDate;

    fn sample_request() -> NewReport {
        NewReport {
            kind: ReportKind::Chargeback,
            format: ReportFormat::Csv,
            requested_by: "1234567890".to_string(),
            site_id: "langley".to_string(),
            start_date: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
        }
    }

    #[tokio::test]
    async fn run_one_returns_none_when_queue_is_empty() {
        let svc: Arc<dyn ReportService> =
            Arc::new(ReportServiceImpl::new(InMemoryReportRepository::new()));
        let noop: GeneratorFn = Arc::new(|_record| {
            Box::pin(async move {
                Ok(GenerationOutcome {
                    row_count: 0,
                    output_location: None,
                })
            })
        });
        let worker = ReportWorker::new(svc, noop);
        assert!(worker.run_one().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn run_one_marks_ready_on_success() {
        let svc: Arc<dyn ReportService> =
            Arc::new(ReportServiceImpl::new(InMemoryReportRepository::new()));
        let enqueued = svc.enqueue(sample_request()).await.unwrap();

        let generator: GeneratorFn = Arc::new(|_record| {
            Box::pin(async move {
                Ok(GenerationOutcome {
                    row_count: 7,
                    output_location: Some("s3://reports/abc.csv".to_string()),
                })
            })
        });
        let worker = ReportWorker::new(Arc::clone(&svc), generator);

        let processed = worker.run_one().await.unwrap().unwrap();
        assert_eq!(processed, enqueued.id);

        let fetched = svc.get(enqueued.id).await.unwrap();
        assert_eq!(fetched.state, ReportState::Ready);
        assert_eq!(fetched.row_count, Some(7));
        assert_eq!(
            fetched.output_location.as_deref(),
            Some("s3://reports/abc.csv")
        );
    }

    #[tokio::test]
    async fn run_one_marks_failed_on_generator_error() {
        let svc: Arc<dyn ReportService> =
            Arc::new(ReportServiceImpl::new(InMemoryReportRepository::new()));
        let enqueued = svc.enqueue(sample_request()).await.unwrap();

        let generator: GeneratorFn = Arc::new(|_record| {
            Box::pin(async move { Err("database timeout".to_string()) })
        });
        let worker = ReportWorker::new(Arc::clone(&svc), generator);

        worker.run_one().await.unwrap();

        let fetched = svc.get(enqueued.id).await.unwrap();
        assert_eq!(fetched.state, ReportState::Failed);
        assert_eq!(fetched.failure_reason.as_deref(), Some("database timeout"));
    }
}
