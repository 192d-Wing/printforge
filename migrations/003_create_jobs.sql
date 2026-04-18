-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 003: Create jobs table
-- NIST 800-53 Rev 5: AU-2 — Event Logging, AU-12 — Audit Record Generation
--
-- Tracks the full lifecycle of print jobs: ingestion, hold, release,
-- printing, completion, and purge. Job IDs are UUIDv7 (time-ordered).
-- The owner_edipi references the users table via the EDIPI unique index.

BEGIN;

CREATE TABLE IF NOT EXISTS jobs (
    id                  UUID        PRIMARY KEY,
    owner_edipi         TEXT        NOT NULL REFERENCES users (edipi),
    document_name       TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'Held'
                                    CHECK (status IN (
                                        'Held', 'Waiting', 'Releasing', 'Printing',
                                        'Completed', 'Failed', 'Purged'
                                    )),
    copies              INTEGER     NOT NULL DEFAULT 1,
    sides               TEXT        NOT NULL DEFAULT 'OneSided'
                                    CHECK (sides IN ('OneSided', 'TwoSidedLongEdge', 'TwoSidedShortEdge')),
    color_mode          TEXT        NOT NULL DEFAULT 'AutoDetect'
                                    CHECK (color_mode IN ('Color', 'Grayscale', 'AutoDetect')),
    media_size          TEXT        NOT NULL DEFAULT 'Letter'
                                    CHECK (media_size IN ('Letter', 'Legal', 'Ledger', 'A4', 'A3')),
    cost_center_code    TEXT        NOT NULL,
    cost_center_name    TEXT        NOT NULL,
    page_count          INTEGER,
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at         TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ
);

-- Query pattern: list jobs by owner (Follow-Me: "show my held jobs").
CREATE INDEX IF NOT EXISTS idx_jobs_owner_edipi ON jobs (owner_edipi);

-- Query pattern: list jobs by status (e.g., find all held or waiting jobs).
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);

-- Query pattern: time-range queries for reporting and retention.
CREATE INDEX IF NOT EXISTS idx_jobs_submitted_at ON jobs (submitted_at DESC);

-- Query pattern: find jobs by cost center for chargeback.
CREATE INDEX IF NOT EXISTS idx_jobs_cost_center_code ON jobs (cost_center_code);

-- Query pattern: retention purge — find completed/failed jobs older than TTL.
CREATE INDEX IF NOT EXISTS idx_jobs_status_completed_at ON jobs (status, completed_at)
    WHERE status IN ('Completed', 'Failed');

COMMIT;
