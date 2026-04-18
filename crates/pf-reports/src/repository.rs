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
    }
}
