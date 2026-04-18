// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for the append-only `audit_events` `PostgreSQL` table.
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! The repository trait enforces append-only semantics at the Rust API level.
//! The `PostgreSQL` migration enforces it at the database level with
//! `REVOKE UPDATE, DELETE ON audit_events FROM printforge_app`.

use pf_common::audit::AuditEvent;

use crate::error::AuditError;
use crate::query::{AuditQuery, AuditQueryResult};

/// Repository trait for append-only audit event storage.
///
/// **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
///
/// This trait intentionally has NO `update` or `delete` methods.
/// Audit records are immutable once written.
pub trait AuditRepository: Send + Sync {
    /// Insert a single audit event into the append-only store.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Persistence` if the database write fails.
    fn insert(
        &self,
        event: &AuditEvent,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send;

    /// Query the audit store with the given filters.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Persistence` on database errors, or
    /// `AuditError::InvalidQuery` if the query is malformed.
    fn query(
        &self,
        query: &AuditQuery,
    ) -> impl std::future::Future<Output = Result<AuditQueryResult, AuditError>> + Send;

    /// Count all records currently in the online store.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::Persistence` on database errors.
    fn count_online(&self) -> impl std::future::Future<Output = Result<u64, AuditError>> + Send;
}

/// SQL for the append-only `audit_events` table migration.
///
/// **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
///
/// Note: The `REVOKE UPDATE, DELETE` statement ensures that even if application
/// code attempted an UPDATE or DELETE, `PostgreSQL` would reject it.
pub const CREATE_AUDIT_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS audit_events (
    id            UUID        PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_edipi   TEXT        NOT NULL,
    action        TEXT        NOT NULL,
    target        TEXT        NOT NULL,
    outcome       TEXT        NOT NULL,
    source_ip     INET        NOT NULL,
    nist_control  TEXT,
    payload       JSONB       NOT NULL DEFAULT '{}'::jsonb
);

-- NIST AU-9: Append-only — revoke modification privileges
REVOKE UPDATE, DELETE ON audit_events FROM printforge_app;

-- Index for common query patterns (AU-6: Audit Record Review)
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor     ON audit_events (actor_edipi);
CREATE INDEX IF NOT EXISTS idx_audit_events_action    ON audit_events (action);
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome   ON audit_events (outcome);
";

/// SQL for the archive table (compressed, long-term storage).
pub const CREATE_ARCHIVE_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS audit_events_archive (
    id            UUID        PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL,
    actor_edipi   TEXT        NOT NULL,
    action        TEXT        NOT NULL,
    target        TEXT        NOT NULL,
    outcome       TEXT        NOT NULL,
    source_ip     INET        NOT NULL,
    nist_control  TEXT,
    payload       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    archived_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Archive table is also append-only for the app role
REVOKE UPDATE, DELETE ON audit_events_archive FROM printforge_app;
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_au9_migration_contains_revoke_update_delete() {
        // NIST 800-53 Rev 5: AU-9 — Protection of Audit Information
        // Evidence: The migration SQL contains REVOKE UPDATE, DELETE
        assert!(
            CREATE_AUDIT_TABLE_SQL.contains("REVOKE UPDATE, DELETE"),
            "Migration must revoke UPDATE and DELETE on audit_events"
        );
    }

    #[test]
    fn nist_au9_archive_migration_contains_revoke() {
        assert!(
            CREATE_ARCHIVE_TABLE_SQL.contains("REVOKE UPDATE, DELETE"),
            "Archive migration must also revoke UPDATE and DELETE"
        );
    }

    #[test]
    fn migration_creates_timestamp_index() {
        assert!(CREATE_AUDIT_TABLE_SQL.contains("idx_audit_events_timestamp"));
    }

    #[test]
    fn migration_creates_actor_index() {
        assert!(CREATE_AUDIT_TABLE_SQL.contains("idx_audit_events_actor"));
    }
}
