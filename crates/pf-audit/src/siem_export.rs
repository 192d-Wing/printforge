// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `CEF` (Common Event Format) string formatter for SIEM integration.
//!
//! **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, Analysis, and Reporting
//! Events are formatted as `CEF` strings for `Splunk`, `Elastic`, or `ACAS`.
//! Transport MUST use TLS (enforced at the config layer).

use pf_common::audit::AuditEvent;

use crate::event_catalog::nist_controls_for;

/// Formats `AuditEvent` values as `CEF` (Common Event Format) strings.
///
/// CEF format: `CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extension`
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
pub struct CefFormatter {
    vendor: String,
    product: String,
    version: String,
}

impl CefFormatter {
    /// Create a new `CEF` formatter with the given vendor, product, and version.
    #[must_use]
    pub fn new(vendor: &str, product: &str, version: &str) -> Self {
        Self {
            vendor: vendor.to_string(),
            product: product.to_string(),
            version: version.to_string(),
        }
    }

    /// Format a single `AuditEvent` as a `CEF` string.
    ///
    /// The actor EDIPI is included via `as_str()` for SIEM correlation but
    /// NEVER in user-facing logs (Display/Debug are redacted).
    ///
    /// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
    #[must_use]
    pub fn format(&self, event: &AuditEvent) -> String {
        let controls = nist_controls_for(event.action);
        let severity = controls.first().map_or(3, |c| c.cef_severity);
        let event_id = format!("{:?}", event.action);
        let name = format!("{:?}", event.action);

        // CEF extension key=value pairs
        // Actor EDIPI is included for SIEM correlation (the SIEM is a
        // controlled, authorized system — not a user-facing log).
        let extension = format!(
            "suser={} dst={} outcome={:?} src={} nist={} eventId={}",
            event.actor.as_str(),
            cef_escape(&event.target),
            event.outcome,
            event.source_ip,
            event
                .nist_control
                .as_deref()
                .unwrap_or_else(|| controls.first().map_or("AU-12", |c| c.control_id)),
            event.id,
        );

        format!(
            "CEF:0|{}|{}|{}|{}|{}|{severity}|{extension}",
            cef_escape(&self.vendor),
            cef_escape(&self.product),
            cef_escape(&self.version),
            cef_escape(&event_id),
            cef_escape(&name),
        )
    }
}

/// Escape special characters in `CEF` header and extension values.
///
/// Per the `CEF` spec, the pipe character `|` and backslash `\` must be escaped
/// in header fields; `=` must also be escaped in extension values.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;
    use pf_common::audit::{EventKind, Outcome};
    use pf_common::identity::Edipi;
    use uuid::Uuid;

    use super::*;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: Edipi::new("1234567890").unwrap(),
            action: EventKind::AuthSuccess,
            target: "login-portal".to_string(),
            outcome: Outcome::Success,
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            nist_control: Some("IA-2".to_string()),
        }
    }

    #[test]
    fn nist_au6_cef_format_contains_required_fields() {
        // NIST 800-53 Rev 5: AU-6 — Audit Record Review
        // Evidence: CEF output contains all required header fields and
        // extension key-value pairs for SIEM ingestion.
        let formatter = CefFormatter::new("PrintForge", "pf-audit", "0.1.0");
        let event = sample_event();
        let cef = formatter.format(&event);

        assert!(cef.starts_with("CEF:0|"));
        assert!(cef.contains("PrintForge"));
        assert!(cef.contains("pf-audit"));
        assert!(cef.contains("0.1.0"));
        assert!(cef.contains("suser=1234567890"));
        assert!(cef.contains("dst=login-portal"));
        assert!(cef.contains("outcome=Success"));
        assert!(cef.contains("src=10.0.0.1"));
        assert!(cef.contains("nist=IA-2"));
    }

    #[test]
    fn nist_au6_cef_escapes_pipe_characters() {
        let formatter = CefFormatter::new("Print|Forge", "pf-audit", "0.1.0");
        let event = sample_event();
        let cef = formatter.format(&event);

        assert!(cef.contains("Print\\|Forge"));
    }

    #[test]
    fn cef_escape_handles_backslash() {
        assert_eq!(cef_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn cef_escape_handles_equals() {
        assert_eq!(cef_escape("key=val"), "key\\=val");
    }

    #[test]
    fn nist_au6_cef_severity_matches_event_kind() {
        let formatter = CefFormatter::new("PrintForge", "pf-audit", "0.1.0");

        // PinLockout should have severity 8
        let mut event = sample_event();
        event.action = EventKind::PinLockout;
        let cef = formatter.format(&event);
        assert!(cef.contains("|8|"), "PinLockout should have CEF severity 8");
    }
}
