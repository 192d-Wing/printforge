// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Core report types: kind, format, state, and the persisted record.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The kind of report to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportKind {
    /// Cost chargeback by cost center / organization.
    Chargeback,
    /// Printer utilization (pages, uptime, idle time).
    Utilization,
    /// Quota compliance (users near or over quota).
    QuotaCompliance,
    /// Waste reduction (duplex adoption, color vs. grayscale).
    WasteReduction,
}

/// Output format for the generated artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportFormat {
    /// JSON, returned inline for dashboard rendering.
    Json,
    /// CSV, downloaded via `output_location`.
    Csv,
}

/// Lifecycle state of a report request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportState {
    /// Persisted, waiting for a worker to pick it up.
    Pending,
    /// A worker is actively generating the artifact.
    Generating,
    /// Generation succeeded; `output_location` holds the artifact path.
    Ready,
    /// Generation failed; `failure_reason` holds the diagnostic.
    Failed,
}

/// Parameters for enqueueing a new report generation request.
#[derive(Debug, Clone)]
pub struct NewReport {
    /// Kind of report to generate.
    pub kind: ReportKind,
    /// Desired output format.
    pub format: ReportFormat,
    /// EDIPI of the requester (used for audit trail + retrieval scoping).
    pub requested_by: String,
    /// Optional site filter — empty string means "no site filter".
    pub site_id: String,
    /// Inclusive start date of the reporting period.
    pub start_date: NaiveDate,
    /// Inclusive end date of the reporting period.
    pub end_date: NaiveDate,
}

/// A report row persisted to the database.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRecord {
    /// Unique report identifier.
    pub id: Uuid,
    /// Kind of report.
    pub kind: ReportKind,
    /// Output format.
    pub format: ReportFormat,
    /// EDIPI of the requester.
    pub requested_by: String,
    /// When the request was persisted.
    pub requested_at: DateTime<Utc>,
    /// Optional site filter; empty string means "no site filter".
    pub site_id: String,
    /// Inclusive start date.
    pub start_date: NaiveDate,
    /// Inclusive end date.
    pub end_date: NaiveDate,
    /// Current lifecycle state.
    pub state: ReportState,
    /// Total rows, populated when `state == Ready`.
    pub row_count: Option<u64>,
    /// Artifact path in object storage, populated when `state == Ready`.
    pub output_location: Option<String>,
    /// Failure diagnostic, populated when `state == Failed`.
    pub failure_reason: Option<String>,
    /// When generation transitioned out of `Pending` / `Generating`.
    pub completed_at: Option<DateTime<Utc>>,
}
