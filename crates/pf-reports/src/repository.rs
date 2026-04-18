// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Report persistence interface.

use std::future::Future;

use uuid::Uuid;

use crate::error::ReportError;
use crate::types::{NewReport, ReportRecord};

/// Persistence interface for `reports` rows.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
pub trait ReportRepository: Send + Sync {
    /// Insert a new `Pending` report request and return the canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn enqueue(
        &self,
        new: &NewReport,
    ) -> impl Future<Output = Result<ReportRecord, ReportError>> + Send;

    /// Fetch a report by id.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::NotFound`] if no report has the given id.
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn get_by_id(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<ReportRecord, ReportError>> + Send;

    /// Atomically claim the next `Pending` report for a worker, transitioning
    /// it to `Generating`. Returns `None` if no pending work is available.
    ///
    /// The pg implementation uses `SELECT ... FOR UPDATE SKIP LOCKED` so
    /// multiple workers can run in parallel without double-claiming.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn claim_next_pending(
        &self,
    ) -> impl Future<Output = Result<Option<ReportRecord>, ReportError>> + Send;

    /// Mark a `Generating` row as `Ready`, recording the row count and the
    /// artifact location (object-store path).
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::NotFound`] if no report has the given id.
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn mark_ready(
        &self,
        id: Uuid,
        row_count: u64,
        output_location: Option<String>,
    ) -> impl Future<Output = Result<(), ReportError>> + Send;

    /// Mark a `Generating` row as `Failed`, recording a diagnostic for
    /// display in the admin UI.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::NotFound`] if no report has the given id.
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn mark_failed(
        &self,
        id: Uuid,
        reason: String,
    ) -> impl Future<Output = Result<(), ReportError>> + Send;
}

// ── In-memory mock for tests ──────────────────────────────────────────────

#[cfg(test)]
pub(crate) use in_memory::InMemoryReportRepository;

#[cfg(test)]
mod in_memory {
    use super::{NewReport, ReportError, ReportRecord, ReportRepository};
    use crate::types::ReportState;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// In-memory [`ReportRepository`] for tests.
    #[derive(Default)]
    pub struct InMemoryReportRepository {
        reports: Mutex<HashMap<Uuid, ReportRecord>>,
    }

    impl InMemoryReportRepository {
        /// Create an empty repository.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl ReportRepository for InMemoryReportRepository {
        async fn enqueue(&self, new: &NewReport) -> Result<ReportRecord, ReportError> {
            let record = ReportRecord {
                id: Uuid::now_v7(),
                kind: new.kind,
                format: new.format,
                requested_by: new.requested_by.clone(),
                requested_at: Utc::now(),
                site_id: new.site_id.clone(),
                start_date: new.start_date,
                end_date: new.end_date,
                state: ReportState::Pending,
                row_count: None,
                output_location: None,
                failure_reason: None,
                completed_at: None,
            };
            let mut map = self.reports.lock().unwrap();
            map.insert(record.id, record.clone());
            Ok(record)
        }

        async fn get_by_id(&self, id: Uuid) -> Result<ReportRecord, ReportError> {
            let map = self.reports.lock().unwrap();
            map.get(&id).cloned().ok_or(ReportError::NotFound)
        }

        async fn claim_next_pending(&self) -> Result<Option<ReportRecord>, ReportError> {
            let mut map = self.reports.lock().unwrap();
            // Pick the oldest Pending row for deterministic test behavior.
            let claim_id = map
                .values()
                .filter(|r| r.state == ReportState::Pending)
                .min_by_key(|r| r.requested_at)
                .map(|r| r.id);

            if let Some(id) = claim_id {
                if let Some(r) = map.get_mut(&id) {
                    r.state = ReportState::Generating;
                    return Ok(Some(r.clone()));
                }
            }
            Ok(None)
        }

        async fn mark_ready(
            &self,
            id: Uuid,
            row_count: u64,
            output_location: Option<String>,
        ) -> Result<(), ReportError> {
            let mut map = self.reports.lock().unwrap();
            let r = map.get_mut(&id).ok_or(ReportError::NotFound)?;
            r.state = ReportState::Ready;
            r.row_count = Some(row_count);
            r.output_location = output_location;
            r.completed_at = Some(Utc::now());
            r.failure_reason = None;
            Ok(())
        }

        async fn mark_failed(
            &self,
            id: Uuid,
            reason: String,
        ) -> Result<(), ReportError> {
            let mut map = self.reports.lock().unwrap();
            let r = map.get_mut(&id).ok_or(ReportError::NotFound)?;
            r.state = ReportState::Failed;
            r.failure_reason = Some(reason);
            r.completed_at = Some(Utc::now());
            Ok(())
        }
    }
}
