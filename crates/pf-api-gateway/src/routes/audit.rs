// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Audit routes: query audit events and export NIST compliance evidence.
//!
//! **NIST 800-53 Rev 5:** AU-6 — Audit Record Review,
//! AC-3 — Access Enforcement (auditor role required).

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{RequireAuth, is_auditor};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Query parameters for searching audit events.
#[derive(Debug, Deserialize)]
pub struct AuditEventsQuery {
    /// Filter by actor EDIPI.
    pub actor: Option<String>,
    /// Filter by event action type.
    pub action: Option<String>,
    /// Start of time range (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// End of time range (inclusive).
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results (default 100).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// A single audit event in a query response.
#[derive(Debug, Serialize)]
pub struct AuditEventSummary {
    /// Event identifier.
    pub id: Uuid,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The actor's EDIPI.
    pub actor: String,
    /// The action performed.
    pub action: String,
    /// The target resource.
    pub target: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Source IP address.
    pub source_ip: String,
}

/// Response for listing audit events.
#[derive(Debug, Serialize)]
pub struct ListAuditEventsResponse {
    /// Matching audit events.
    pub events: Vec<AuditEventSummary>,
    /// Total count for pagination.
    pub total: u64,
}

/// Query parameters for NIST evidence export.
#[derive(Debug, Deserialize)]
pub struct NistEvidenceQuery {
    /// NIST 800-53 control family to export evidence for (e.g., `"AC"`, `"AU"`).
    pub control_family: Option<String>,
    /// Start of time range.
    pub from: Option<DateTime<Utc>>,
    /// End of time range.
    pub to: Option<DateTime<Utc>>,
}

/// A single NIST compliance evidence record.
#[derive(Debug, Serialize)]
pub struct NistEvidenceRecord {
    /// The NIST 800-53 control identifier (e.g., `"AC-3"`).
    pub control_id: String,
    /// Human-readable description of the evidence.
    pub description: String,
    /// Number of supporting audit events in the time range.
    pub event_count: u64,
    /// Whether this control is considered satisfied.
    pub satisfied: bool,
}

/// Response for NIST evidence export.
#[derive(Debug, Serialize)]
pub struct NistEvidenceResponse {
    /// The time range of the exported evidence.
    pub from: DateTime<Utc>,
    /// End of the evidence time range.
    pub to: DateTime<Utc>,
    /// Evidence records by control.
    pub controls: Vec<NistEvidenceRecord>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the `/audit` router.
///
/// All routes require the `Auditor` role.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/events", get(list_audit_events))
        .route("/nist-evidence", get(export_nist_evidence))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Query audit events.
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, AC-3 — Access Enforcement.
///
/// # Errors
///
/// Returns `ApiError::forbidden` if the caller does not hold the `Auditor` role.
async fn list_audit_events(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Query(params): Query<AuditEventsQuery>,
) -> Result<Json<ListAuditEventsResponse>, ApiError> {
    if !is_auditor(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let svc = state.audit_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let query = pf_audit::AuditQuery {
        from: params.from,
        to: params.to,
        limit: params.limit,
        offset: params.offset,
        ..Default::default()
    };

    let (events, total) = svc.query_events(query).await.map_err(|e| {
        match e {
            pf_audit::AuditError::InvalidQuery { .. } => {
                ApiError::bad_request(Uuid::now_v7(), e.to_string())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    let summaries = events
        .into_iter()
        .map(|e| AuditEventSummary {
            id: e.id,
            timestamp: e.timestamp,
            actor: e.actor.as_str().to_string(),
            action: format!("{:?}", e.action),
            target: e.target,
            success: e.outcome == pf_common::audit::Outcome::Success,
            source_ip: e.source_ip.to_string(),
        })
        .collect();

    Ok(Json(ListAuditEventsResponse {
        events: summaries,
        total,
    }))
}

/// Export NIST 800-53 compliance evidence for eMASS artifacts.
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, AC-3 — Access Enforcement.
///
/// # Errors
///
/// Returns `ApiError::forbidden` if the caller does not hold the `Auditor` role.
async fn export_nist_evidence(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Query(params): Query<NistEvidenceQuery>,
) -> Result<Json<NistEvidenceResponse>, ApiError> {
    if !is_auditor(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let svc = state.audit_service.as_ref()
        .ok_or_else(|| ApiError::service_unavailable(Uuid::now_v7()))?;

    let now = Utc::now();
    let control_family = params.control_family.as_deref().unwrap_or("AU");
    let from = params.from.unwrap_or(now - chrono::Duration::days(30));
    let to = params.to.unwrap_or(now);

    let report = svc.export_nist_evidence(control_family.to_string(), from, to).await.map_err(|e| {
        match e {
            pf_audit::AuditError::InvalidQuery { .. } => {
                ApiError::bad_request(Uuid::now_v7(), e.to_string())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    let controls = report.artifacts
        .into_iter()
        .map(|a| NistEvidenceRecord {
            control_id: a.control_id,
            description: a.implementation_description,
            event_count: report.total_events,
            satisfied: report.failure_count == 0 || report.success_count > 0,
        })
        .collect();

    Ok(Json(NistEvidenceResponse {
        from: report.from,
        to: report.to,
        controls,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_events_query_defaults() {
        let json = "{}";
        let query: AuditEventsQuery = serde_json::from_str(json).unwrap();
        assert!(query.actor.is_none());
        assert!(query.action.is_none());
    }

    #[test]
    fn nist_evidence_record_serializes() {
        let record = NistEvidenceRecord {
            control_id: "AC-3".to_string(),
            description: "Access enforcement".to_string(),
            event_count: 42,
            satisfied: true,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("AC-3"));
    }
}
