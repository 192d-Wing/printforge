-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 005: Create quota_counters table
-- NIST 800-53 Rev 5: AU-12 — Audit Record Generation
--
-- Tracks per-user page quota consumption for each billing period. Quotas
-- are tracked here (pf-accounting) and enforced by pf-policy-engine.
-- Uses SELECT FOR UPDATE in application code to prevent race conditions
-- on concurrent job submissions.

BEGIN;

CREATE TABLE IF NOT EXISTS quota_counters (
    edipi               TEXT        NOT NULL REFERENCES users (edipi),
    page_limit          INTEGER     NOT NULL DEFAULT 500,
    pages_used          INTEGER     NOT NULL DEFAULT 0,
    color_page_limit    INTEGER     NOT NULL DEFAULT 100,
    color_pages_used    INTEGER     NOT NULL DEFAULT 0,
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    burst_pages_used    INTEGER     NOT NULL DEFAULT 0,
    burst_limit         INTEGER     NOT NULL DEFAULT 50,

    -- Primary key: one counter per user (current billing period).
    -- The application uses ON CONFLICT (edipi) for upsert.
    PRIMARY KEY (edipi),

    -- Ensure period_end is after period_start.
    CHECK (period_end > period_start),

    -- Ensure usage does not go negative.
    CHECK (pages_used >= 0),
    CHECK (color_pages_used >= 0),
    CHECK (burst_pages_used >= 0)
);

-- Query pattern: find the current quota counter for a user.
CREATE INDEX IF NOT EXISTS idx_quota_counters_edipi_period ON quota_counters (edipi, period_end DESC);

-- Query pattern: reset expired quotas (find counters where period_end < now).
CREATE INDEX IF NOT EXISTS idx_quota_counters_period_end ON quota_counters (period_end);

COMMIT;
