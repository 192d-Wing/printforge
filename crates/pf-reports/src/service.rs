// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! High-level report service trait.

use std::future::Future;
use std::pin::Pin;

use uuid::Uuid;

use crate::error::ReportError;
use crate::types::{NewReport, ReportRecord};

/// Service for enqueueing and fetching reports.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
pub trait ReportService: Send + Sync {
    /// Enqueue a report and return the `Pending` record. The actual artifact
    /// is produced by a background worker; clients poll [`Self::get`] for
    /// the current state.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidPeriod`] if `start_date > end_date`.
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn enqueue(
        &self,
        new: NewReport,
    ) -> Pin<Box<dyn Future<Output = Result<ReportRecord, ReportError>> + Send + '_>>;

    /// Look up a report by id.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::NotFound`] if no report has the given id.
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn get(
        &self,
        id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<ReportRecord, ReportError>> + Send + '_>>;
}
