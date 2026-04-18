// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default implementation of [`ReportService`] backed by a [`ReportRepository`].

use std::pin::Pin;

use uuid::Uuid;

use crate::error::ReportError;
use crate::repository::ReportRepository;
use crate::service::ReportService;
use crate::types::{NewReport, ReportRecord};

/// Default `ReportService` implementation.
pub struct ReportServiceImpl<R> {
    repo: R,
}

impl<R> ReportServiceImpl<R> {
    /// Create a new service wrapping `repo`.
    #[must_use]
    pub fn new(repo: R) -> Self {
        Self { repo }
    }
}

impl<R: ReportRepository + 'static> ReportService for ReportServiceImpl<R> {
    fn enqueue(
        &self,
        new: NewReport,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<ReportRecord, ReportError>> + Send + '_>>
    {
        Box::pin(async move {
            if new.start_date > new.end_date {
                return Err(ReportError::InvalidPeriod {
                    reason: format!("start {} is after end {}", new.start_date, new.end_date),
                });
            }
            let record = self.repo.enqueue(&new).await?;
            tracing::info!(
                report_id = %record.id,
                kind = ?record.kind,
                requested_by = %record.requested_by,
                "report enqueued"
            );
            Ok(record)
        })
    }

    fn get(
        &self,
        id: Uuid,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<ReportRecord, ReportError>> + Send + '_>>
    {
        Box::pin(async move { self.repo.get_by_id(id).await })
    }

    fn claim_next_pending(
        &self,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<ReportRecord>, ReportError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let claimed = self.repo.claim_next_pending().await?;
            if let Some(ref r) = claimed {
                tracing::info!(
                    report_id = %r.id,
                    kind = ?r.kind,
                    "report claimed by worker"
                );
            }
            Ok(claimed)
        })
    }

    fn mark_ready(
        &self,
        id: Uuid,
        row_count: u64,
        output_location: Option<String>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), ReportError>> + Send + '_>> {
        Box::pin(async move {
            self.repo.mark_ready(id, row_count, output_location.clone()).await?;
            tracing::info!(
                report_id = %id,
                row_count,
                output_location = ?output_location,
                "report marked Ready"
            );
            Ok(())
        })
    }

    fn mark_failed(
        &self,
        id: Uuid,
        reason: String,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), ReportError>> + Send + '_>> {
        Box::pin(async move {
            self.repo.mark_failed(id, reason.clone()).await?;
            tracing::warn!(
                report_id = %id,
                reason = %reason,
                "report marked Failed"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryReportRepository;
    use crate::types::{ReportFormat, ReportKind, ReportState};
    use chrono::NaiveDate;

    fn sample_request(edipi: &str) -> NewReport {
        NewReport {
            kind: ReportKind::Chargeback,
            format: ReportFormat::Csv,
            requested_by: edipi.to_string(),
            site_id: "langley".to_string(),
            start_date: NaiveDate::from_ymd_opt(2026, 3, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2026, 3, 31).unwrap(),
        }
    }

    #[tokio::test]
    async fn nist_au12_enqueue_persists_pending_row() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        // Evidence: enqueueing a report persists a row, assigns an ID, and
        // records the requester so the act of requesting is itself auditable.
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let record = svc.enqueue(sample_request("1234567890")).await.unwrap();
        assert_eq!(record.state, ReportState::Pending);
        assert_eq!(record.requested_by, "1234567890");
        assert!(record.output_location.is_none());
        assert!(record.failure_reason.is_none());
    }

    #[tokio::test]
    async fn enqueue_rejects_inverted_period() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let mut req = sample_request("1234567890");
        req.start_date = NaiveDate::from_ymd_opt(2026, 4, 1).unwrap();
        req.end_date = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();

        let result = svc.enqueue(req).await;
        assert!(matches!(result, Err(ReportError::InvalidPeriod { .. })));
    }

    #[tokio::test]
    async fn get_returns_enqueued_record() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let created = svc.enqueue(sample_request("1234567890")).await.unwrap();
        let fetched = svc.get(created.id).await.unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.state, ReportState::Pending);
    }

    #[tokio::test]
    async fn get_unknown_id_returns_not_found() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let result = svc.get(Uuid::new_v4()).await;
        assert!(matches!(result, Err(ReportError::NotFound)));
    }

    #[tokio::test]
    async fn claim_next_pending_flips_state_to_generating() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let enqueued = svc.enqueue(sample_request("1234567890")).await.unwrap();

        let claimed = svc.claim_next_pending().await.unwrap().unwrap();
        assert_eq!(claimed.id, enqueued.id);
        assert_eq!(claimed.state, ReportState::Generating);

        // A second claim should return None now that the only row is
        // Generating.
        let next = svc.claim_next_pending().await.unwrap();
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn mark_ready_records_row_count_and_location() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let enqueued = svc.enqueue(sample_request("1234567890")).await.unwrap();
        let _ = svc.claim_next_pending().await.unwrap();

        svc.mark_ready(enqueued.id, 42, Some("s3://bucket/key".to_string()))
            .await
            .unwrap();

        let fetched = svc.get(enqueued.id).await.unwrap();
        assert_eq!(fetched.state, ReportState::Ready);
        assert_eq!(fetched.row_count, Some(42));
        assert_eq!(fetched.output_location.as_deref(), Some("s3://bucket/key"));
        assert!(fetched.completed_at.is_some());
    }

    #[tokio::test]
    async fn mark_failed_records_reason() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let enqueued = svc.enqueue(sample_request("1234567890")).await.unwrap();
        let _ = svc.claim_next_pending().await.unwrap();

        svc.mark_failed(enqueued.id, "database timeout".to_string())
            .await
            .unwrap();

        let fetched = svc.get(enqueued.id).await.unwrap();
        assert_eq!(fetched.state, ReportState::Failed);
        assert_eq!(fetched.failure_reason.as_deref(), Some("database timeout"));
    }

    #[tokio::test]
    async fn mark_ready_unknown_id_returns_not_found() {
        let svc = ReportServiceImpl::new(InMemoryReportRepository::new());
        let result = svc.mark_ready(Uuid::new_v4(), 0, None).await;
        assert!(matches!(result, Err(ReportError::NotFound)));
    }
}
