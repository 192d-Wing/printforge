-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 004: Create audit_events and audit_events_archive tables
-- NIST 800-53 Rev 5: AU-2 — Event Logging
-- NIST 800-53 Rev 5: AU-3 — Content of Audit Records
-- NIST 800-53 Rev 5: AU-9 — Protection of Audit Information
--
-- The audit_events table is append-only. UPDATE and DELETE privileges are
-- revoked from the application role (printforge_app) to enforce immutability
-- at the database level. This satisfies AU-9: Protection of Audit Information.
--
-- Every audit record contains: who (actor_edipi), what (action), when (timestamp),
-- where (source_ip), and outcome — satisfying AU-3.

BEGIN;

-- ── Online audit table (365-day retention, queryable) ──────────────────

CREATE TABLE IF NOT EXISTS audit_events (
    id            UUID        PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_edipi   TEXT        NOT NULL,
    action        TEXT        NOT NULL,
    target        TEXT        NOT NULL,
    outcome       TEXT        NOT NULL CHECK (outcome IN ('Success', 'Failure')),
    source_ip     INET        NOT NULL,
    nist_control  TEXT,
    payload       JSONB       NOT NULL DEFAULT '{}'::jsonb
);

-- NIST AU-9: Append-only — revoke modification privileges from the app role.
-- The application can only INSERT and SELECT; never UPDATE or DELETE.
REVOKE UPDATE, DELETE ON audit_events FROM printforge_app;

-- Index for time-range queries (AU-6: Audit Record Review — dashboards, SIEM).
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp DESC);

-- Index for actor-based queries (who did what).
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor_edipi);

-- Index for action-based queries (find all events of a specific kind).
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action);

-- Index for outcome filtering (find all failures).
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events (outcome);

-- Index for NIST control evidence queries (find all events for a control).
CREATE INDEX IF NOT EXISTS idx_audit_events_nist_control ON audit_events (nist_control)
    WHERE nist_control IS NOT NULL;

-- ── Archive table (7-year retention per DoD 5015.02) ───────────────────

CREATE TABLE IF NOT EXISTS audit_events_archive (
    id            UUID        PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL,
    actor_edipi   TEXT        NOT NULL,
    action        TEXT        NOT NULL,
    target        TEXT        NOT NULL,
    outcome       TEXT        NOT NULL CHECK (outcome IN ('Success', 'Failure')),
    source_ip     INET        NOT NULL,
    nist_control  TEXT,
    payload       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    archived_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Archive table is also append-only for the application role.
REVOKE UPDATE, DELETE ON audit_events_archive FROM printforge_app;

-- Index for time-range queries on archived events.
CREATE INDEX IF NOT EXISTS idx_audit_archive_timestamp ON audit_events_archive (timestamp DESC);

-- Index for actor-based queries on archived events.
CREATE INDEX IF NOT EXISTS idx_audit_archive_actor ON audit_events_archive (actor_edipi);

COMMIT;
