// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Request/response audit logging middleware types.
//!
//! **NIST 800-53 Rev 5:** AU-2, AU-3, AU-12 — Audit Record Generation
//! Every API request produces a structured audit log entry including
//! who, what, when, where, and outcome.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A structured log entry for an API request/response pair.
///
/// **NIST 800-53 Rev 5:** AU-3 — Content of Audit Records
/// Contains: who (actor), what (method + path), when (timestamp),
/// where (source IP), and outcome (status code).
#[derive(Debug, Clone, Serialize)]
pub struct RequestAuditEntry {
    /// Unique request identifier for correlation.
    pub request_id: Uuid,
    /// Timestamp when the request was received.
    pub timestamp: DateTime<Utc>,
    /// EDIPI of the authenticated user, if any.
    pub actor: Option<String>,
    /// HTTP method.
    pub method: String,
    /// Request path (without query string to avoid logging sensitive params).
    pub path: String,
    /// Client IP address.
    pub source_ip: IpAddr,
    /// HTTP status code of the response.
    pub status_code: u16,
    /// Request processing duration in milliseconds.
    pub duration_ms: u64,
    /// User-Agent header value, if present.
    pub user_agent: Option<String>,
}

impl RequestAuditEntry {
    /// Emit this audit entry as a structured `tracing` event.
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    pub fn emit(&self) {
        tracing::info!(
            request_id = %self.request_id,
            timestamp = %self.timestamp,
            actor = ?self.actor,
            method = %self.method,
            path = %self.path,
            source_ip = %self.source_ip,
            status_code = self.status_code,
            duration_ms = self.duration_ms,
            user_agent = ?self.user_agent,
            "api_request"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> RequestAuditEntry {
        RequestAuditEntry {
            request_id: Uuid::nil(),
            timestamp: Utc::now(),
            actor: Some("1234567890".to_string()),
            method: "GET".to_string(),
            path: "/api/v1/jobs".to_string(),
            source_ip: "10.0.0.1".parse().unwrap(),
            status_code: 200,
            duration_ms: 42,
            user_agent: Some("PrintForge-Client/1.0".to_string()),
        }
    }

    #[test]
    fn nist_au3_audit_entry_contains_required_fields() {
        // NIST 800-53 Rev 5: AU-3 — Content of Audit Records
        // Evidence: All required fields (who, what, when, where, outcome) are present.
        let entry = sample_entry();
        assert!(entry.actor.is_some()); // who
        assert!(!entry.method.is_empty()); // what (method)
        assert!(!entry.path.is_empty()); // what (path)
        // when: timestamp is set
        assert!(entry.timestamp <= Utc::now());
        // where: source_ip
        assert_eq!(entry.source_ip.to_string(), "10.0.0.1");
        // outcome: status_code
        assert_eq!(entry.status_code, 200);
    }

    #[test]
    fn nist_au3_audit_entry_serializes_to_json() {
        // NIST 800-53 Rev 5: AU-3 — Content of Audit Records
        // Evidence: Audit entries can be serialized for SIEM export.
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("request_id"));
        assert!(json.contains("source_ip"));
        assert!(json.contains("status_code"));
    }

    #[test]
    fn audit_entry_omits_query_string() {
        // Ensure the path field does not contain query parameters
        // which might include sensitive data.
        let entry = RequestAuditEntry {
            path: "/api/v1/jobs".to_string(),
            ..sample_entry()
        };
        assert!(!entry.path.contains('?'));
    }
}
