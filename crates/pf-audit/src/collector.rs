// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Audit event collector: receives `AuditEvent` values from all crates,
//! validates the schema, and dispatches to the writer and SIEM exporter.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
//! The collector is the single entry point for all audit events across
//! `PrintForge`. It validates each event against AU-3 requirements before
//! persisting.

use pf_common::audit::AuditEvent;
use tracing::{error, info};

use crate::error::AuditError;
use crate::event_catalog::primary_control_id;
use crate::siem_export::CefFormatter;
use crate::writer::AuditWriter;

/// Validates that an `AuditEvent` meets NIST AU-3 schema requirements.
///
/// **NIST 800-53 Rev 5:** AU-3 — Content of Audit Records
///
/// # Errors
///
/// Returns `AuditError::Validation` if any required field is missing or invalid.
pub fn validate_event(event: &AuditEvent) -> Result<(), AuditError> {
    // AU-3 requires: who, what, when, where, outcome
    // "who" — actor EDIPI is a validated newtype, always present
    // "what" — action (EventKind) is always present (enum)
    // "when" — timestamp is always present (DateTime<Utc>)
    // "where" — source_ip is always present (IpAddr)
    // "outcome" — always present (enum)

    // Target must not be empty
    if event.target.trim().is_empty() {
        return Err(AuditError::Validation {
            message: "event target must not be empty".to_string(),
        });
    }

    // Target must not exceed 1024 characters to prevent abuse
    if event.target.len() > 1024 {
        return Err(AuditError::Validation {
            message: "event target exceeds maximum length of 1024".to_string(),
        });
    }

    Ok(())
}

/// The audit collector receives events and dispatches them to the
/// persistence layer and optional SIEM export.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
pub struct AuditCollector<W: AuditWriter> {
    writer: W,
    cef_formatter: CefFormatter,
    siem_enabled: bool,
}

impl<W: AuditWriter> AuditCollector<W> {
    /// Create a new `AuditCollector` with the given writer and SIEM settings.
    #[must_use]
    pub fn new(writer: W, siem_enabled: bool) -> Self {
        Self {
            writer,
            cef_formatter: CefFormatter::new("PrintForge", "pf-audit", "0.1.0"),
            siem_enabled,
        }
    }

    /// Collect a single audit event: validate, persist, and optionally export.
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    ///
    /// Per security requirements, if the write fails the originating operation
    /// MUST still succeed, but an alert is emitted. This method logs errors
    /// rather than propagating them to avoid blocking callers.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Validation` if the event fails schema validation.
    /// Persistence errors are logged but not propagated.
    pub async fn collect(&self, event: AuditEvent) -> Result<(), AuditError> {
        validate_event(&event)?;

        // Enrich with NIST control if not already set
        let event = if event.nist_control.is_none() {
            let mut enriched = event;
            enriched.nist_control = Some(primary_control_id(enriched.action).to_string());
            enriched
        } else {
            event
        };

        // Persist — log errors but do not fail the caller
        if let Err(e) = self.writer.write(&event).await {
            error!(
                event_id = %event.id,
                action = ?event.action,
                "AU-9: audit write failed — event may be lost: {e}"
            );
        } else {
            info!(
                event_id = %event.id,
                action = ?event.action,
                "AU-12: audit event persisted"
            );
        }

        // SIEM export (best-effort)
        if self.siem_enabled {
            let cef_line = self.cef_formatter.format(&event);
            // In production this would be sent over TLS to the SIEM endpoint.
            // Here we log it as structured output for the SIEM forwarder to pick up.
            info!(cef = %cef_line, "AU-6: CEF event exported for SIEM");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;
    use pf_common::audit::{EventKind, Outcome};
    use pf_common::identity::Edipi;
    use uuid::Uuid;

    use super::*;
    use crate::writer::InMemoryWriter;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: Edipi::new("1234567890").unwrap(),
            action: EventKind::AuthSuccess,
            target: "login-portal".to_string(),
            outcome: Outcome::Success,
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            nist_control: None,
        }
    }

    #[test]
    fn nist_au3_validates_non_empty_target() {
        // NIST 800-53 Rev 5: AU-3 — Content of Audit Records
        // Evidence: Events with empty targets are rejected
        let mut event = sample_event();
        event.target = String::new();
        assert!(validate_event(&event).is_err());
    }

    #[test]
    fn nist_au3_validates_target_max_length() {
        let mut event = sample_event();
        event.target = "x".repeat(1025);
        assert!(validate_event(&event).is_err());
    }

    #[test]
    fn nist_au3_accepts_valid_event() {
        // NIST 800-53 Rev 5: AU-3 — Content of Audit Records
        // Evidence: A fully-populated event passes validation
        let event = sample_event();
        assert!(validate_event(&event).is_ok());
    }

    #[tokio::test]
    async fn nist_au12_collector_persists_event() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        // Evidence: Collector writes event to the persistence layer
        let writer = InMemoryWriter::new();
        let collector = AuditCollector::new(writer.clone(), false);
        let event = sample_event();
        let event_id = event.id;

        collector.collect(event).await.unwrap();

        let events = writer.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event_id);
    }

    #[tokio::test]
    async fn collector_enriches_nist_control() {
        let writer = InMemoryWriter::new();
        let collector = AuditCollector::new(writer.clone(), false);
        let event = sample_event();

        collector.collect(event).await.unwrap();

        let events = writer.events();
        assert_eq!(events[0].nist_control.as_deref(), Some("IA-2"));
    }

    #[tokio::test]
    async fn collector_preserves_existing_nist_control() {
        let writer = InMemoryWriter::new();
        let collector = AuditCollector::new(writer.clone(), false);
        let mut event = sample_event();
        event.nist_control = Some("AC-7".to_string());

        collector.collect(event).await.unwrap();

        let events = writer.events();
        assert_eq!(events[0].nist_control.as_deref(), Some("AC-7"));
    }
}
