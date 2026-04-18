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
}
