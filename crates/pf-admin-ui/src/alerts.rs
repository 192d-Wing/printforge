// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Alert feed types for the admin dashboard: active alerts, severity levels,
//! and acknowledgment workflow.
//!
//! **NIST 800-53 Rev 5:** SI-4 — Information System Monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterId;
use pf_common::identity::SiteId;

/// Severity level for an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational notice; no immediate action required.
    Info,
    /// Warning that may require attention soon.
    Warning,
    /// Critical issue requiring immediate attention.
    Critical,
}

/// The category of the alert source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertCategory {
    /// Printer went offline or entered error state.
    PrinterStatus,
    /// Supply levels critically low.
    SupplyLow,
    /// Firmware deployment issue.
    Firmware,
    /// Security-related alert (auth failures, policy violations).
    Security,
    /// Quota threshold exceeded.
    Quota,
    /// Cache node connectivity / DDIL event.
    CacheNode,
}

/// Current state of an alert in the acknowledgment workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertState {
    /// Alert is active and unacknowledged.
    Active,
    /// Alert has been acknowledged by an administrator.
    Acknowledged,
    /// Alert condition has been resolved.
    Resolved,
}

/// An alert displayed in the admin dashboard feed.
///
/// **NIST 800-53 Rev 5:** SI-4 — Information System Monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert identifier.
    pub alert_id: Uuid,

    /// Severity level.
    pub severity: AlertSeverity,

    /// Alert category.
    pub category: AlertCategory,

    /// Current state.
    pub state: AlertState,

    /// Human-readable alert title.
    pub title: String,

    /// Detailed description of the alert condition.
    pub description: String,

    /// Site where the alert originated.
    pub site_id: SiteId,

    /// Affected printer (if applicable).
    pub printer_id: Option<PrinterId>,

    /// When the alert was created.
    pub created_at: DateTime<Utc>,

    /// When the alert was acknowledged (if applicable).
    pub acknowledged_at: Option<DateTime<Utc>>,

    /// Display name of the admin who acknowledged (if applicable).
    pub acknowledged_by: Option<String>,

    /// When the alert was resolved (if applicable).
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Request to acknowledge an active alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgeAlertRequest {
    /// The alert to acknowledge.
    pub alert_id: Uuid,

    /// Optional note from the acknowledging admin.
    pub note: Option<String>,
}

/// Filters for querying alerts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertFilter {
    /// Filter by site.
    pub site_id: Option<SiteId>,

    /// Filter by severity.
    pub severity: Option<AlertSeverity>,

    /// Filter by category.
    pub category: Option<AlertCategory>,

    /// Filter by state.
    pub state: Option<AlertState>,

    /// Only show alerts created after this timestamp.
    pub created_after: Option<DateTime<Utc>>,
}

/// Paginated alert response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertListResponse {
    /// Alerts for the current page.
    pub alerts: Vec<Alert>,

    /// Total number of alerts matching the filter.
    pub total_count: u64,

    /// Current page number.
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_filter_default_is_unfiltered() {
        let filter = AlertFilter::default();
        assert!(filter.site_id.is_none());
        assert!(filter.severity.is_none());
        assert!(filter.category.is_none());
        assert!(filter.state.is_none());
    }

    #[test]
    fn alert_severity_all_variants_serialize() {
        let severities = vec![
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Critical,
        ];
        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let deserialized: AlertSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, severity);
        }
    }

    #[test]
    fn acknowledge_request_serialization() {
        let req = AcknowledgeAlertRequest {
            alert_id: Uuid::nil(),
            note: Some("Investigating printer jam".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: AcknowledgeAlertRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.alert_id, Uuid::nil());
        assert!(deserialized.note.is_some());
    }
}
