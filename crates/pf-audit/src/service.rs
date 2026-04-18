// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `AuditService` trait: business-logic layer for audit queries and NIST
//! evidence export.
//!
//! **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, Analysis, and Reporting
//! Provides the application-level interface consumed by `pf-api-gateway` for
//! the `/api/v1/audit/events` and `/api/v1/audit/nist-evidence` endpoints.

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use pf_common::audit::AuditEvent;
use serde::{Deserialize, Serialize};

use crate::emass::EmassArtifact;
use crate::error::AuditError;
use crate::query::AuditQuery;

/// A NIST 800-53 evidence report for a specific control family over a time
/// window.
///
/// Aggregates matching audit events with summary statistics and eMASS
/// artifacts, suitable for RMF continuous monitoring evidence packages.
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistEvidenceReport {
    /// The NIST 800-53 control family (e.g., "AU", "IA", "AC").
    pub control_family: String,

    /// Start of the reporting period (inclusive).
    pub from: DateTime<Utc>,

    /// End of the reporting period (exclusive).
    pub to: DateTime<Utc>,

    /// When this report was generated.
    pub generated_at: DateTime<Utc>,

    /// Total number of events matching the control family in the period.
    pub total_events: u64,

    /// Number of events with `Outcome::Success`.
    pub success_count: u64,

    /// Number of events with `Outcome::Failure`.
    pub failure_count: u64,

    /// The matching events (paginated; up to 10,000 per report).
    pub events: Vec<AuditEvent>,

    /// Generated eMASS artifacts for the control family.
    pub artifacts: Vec<EmassArtifact>,
}

/// Application-level audit service trait.
///
/// Abstracts the query and reporting layer so that `pf-api-gateway` does not
/// depend on repository details.
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, Analysis, and Reporting
#[allow(clippy::type_complexity)]
pub trait AuditService: Send + Sync {
    /// Query audit events with the given filters, returning the matching
    /// events and the total count (for pagination).
    ///
    /// The query is validated before execution.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::InvalidQuery` if the query is malformed, or
    /// `AuditError::Persistence` on database errors.
    fn query_events(
        &self,
        query: AuditQuery,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<AuditEvent>, u64), AuditError>> + Send + '_>>;

    /// Generate a NIST 800-53 evidence report for the given control family
    /// over a time window.
    ///
    /// The report aggregates matching events, computes summary statistics,
    /// and attaches relevant eMASS artifacts.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::InvalidQuery` if `from >= to` or the control
    /// family is empty, or `AuditError::Persistence` on database errors.
    fn export_nist_evidence(
        &self,
        control_family: String,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = Result<NistEvidenceReport, AuditError>> + Send + '_>>;
}
