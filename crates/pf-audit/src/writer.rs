// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Audit writer trait and implementations for append-only audit persistence.
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! The writer trait enforces append-only semantics: there is no `update` or
//! `delete` method. The `PostgreSQL` implementation relies on database-level
//! `REVOKE UPDATE, DELETE` grants.

use std::sync::{Arc, Mutex};

use pf_common::audit::AuditEvent;

use crate::error::AuditError;

/// Trait for append-only audit event persistence.
///
/// **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
///
/// Implementations MUST be append-only. There is intentionally no `update`
/// or `delete` method on this trait.
pub trait AuditWriter: Send + Sync {
    /// Append a single audit event to the persistent store.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Persistence` if the write fails.
    fn write(
        &self,
        event: &AuditEvent,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send;
}

/// An in-memory append-only writer for testing.
///
/// Thread-safe via `Arc<Mutex<Vec<AuditEvent>>>`.
#[derive(Debug, Clone)]
pub struct InMemoryWriter {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl InMemoryWriter {
    /// Create a new empty in-memory writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return a snapshot of all collected events.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("lock poisoned").clone()
    }
}

impl Default for InMemoryWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditWriter for InMemoryWriter {
    async fn write(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .expect("lock poisoned")
            .push(event.clone());
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

    #[tokio::test]
    async fn nist_au9_in_memory_writer_is_append_only() {
        // NIST 800-53 Rev 5: AU-9 — Protection of Audit Information
        // Evidence: The writer trait has no update/delete; in-memory writer
        // only appends.
        let writer = InMemoryWriter::new();
        let event = AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: Edipi::new("1234567890").unwrap(),
            action: EventKind::AuthSuccess,
            target: "test-target".to_string(),
            outcome: Outcome::Success,
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            nist_control: Some("IA-2".to_string()),
        };

        writer.write(&event).await.unwrap();
        writer.write(&event).await.unwrap();

        assert_eq!(writer.events().len(), 2);
    }
}
