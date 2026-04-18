// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! High-level report service trait.

use std::future::Future;
use std::pin::Pin;

use uuid::Uuid;

use crate::error::ReportError;
use crate::types::{NewReport, ReportRecord};

/// Service for enqueueing and fetching reports, and for the worker to drive
/// state transitions.
///
/// The admin dashboard uses only [`Self::enqueue`] and [`Self::get`]. The
/// remaining methods are the worker's half of the contract:
/// [`Self::claim_next_pending`] picks up a Pending row (atomically flipping
/// it to Generating), then the worker calls [`Self::mark_ready`] or
/// [`Self::mark_failed`] depending on the outcome.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
#[allow(clippy::type_complexity)]
pub trait ReportService: Send + Sync {
    /// Enqueue a report and return the `Pending` record.
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

    /// Claim the next Pending report for a worker, atomically transitioning
    /// it to `Generating`. Returns `None` when no work is available.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Repository`] on persistence failure.
    fn claim_next_pending(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<ReportRecord>, ReportError>> + Send + '_>,
    >;

    /// Transition a Generating row to Ready with the final row count and
    /// optional artifact location.
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
    ) -> Pin<Box<dyn Future<Output = Result<(), ReportError>> + Send + '_>>;

    /// Transition a Generating row to Failed, recording a diagnostic for
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
    ) -> Pin<Box<dyn Future<Output = Result<(), ReportError>> + Send + '_>>;
}
