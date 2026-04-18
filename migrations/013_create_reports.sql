-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 013: Create reports table
-- NIST 800-53 Rev 5: AU-2, AU-12 — Report generation and export are
-- auditable events.
--
-- Report generation is intentionally async: the admin dashboard POSTs a
-- request, we persist a Pending row and return the id immediately, and a
-- worker (future slice) picks up pending rows and writes artifacts to
-- object storage before transitioning to Ready. This decouples the admin
-- request from the actual generation, which may be slow or memory-heavy.

BEGIN;

CREATE TABLE IF NOT EXISTS reports (
    id               UUID        PRIMARY KEY,
    kind             TEXT        NOT NULL
                                 CHECK (kind IN (
                                     'Chargeback', 'Utilization',
                                     'QuotaCompliance', 'WasteReduction'
                                 )),
    format           TEXT        NOT NULL
                                 CHECK (format IN ('Json', 'Csv')),
    requested_by     TEXT        NOT NULL,
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    site_id          TEXT        NOT NULL DEFAULT '',
    start_date       DATE        NOT NULL,
    end_date         DATE        NOT NULL,
    state            TEXT        NOT NULL DEFAULT 'Pending'
                                 CHECK (state IN (
                                     'Pending', 'Generating',
                                     'Ready', 'Failed'
                                 )),
    row_count        BIGINT,
    output_location  TEXT,
    failure_reason   TEXT,
    completed_at     TIMESTAMPTZ,

    CHECK (start_date <= end_date)
);

-- Query pattern: worker picks up oldest pending jobs (claim order).
CREATE INDEX IF NOT EXISTS idx_reports_state_pending
    ON reports (requested_at)
    WHERE state = 'Pending';

-- Query pattern: admin dashboard lists a user's recent reports.
CREATE INDEX IF NOT EXISTS idx_reports_requested_by
    ON reports (requested_by, requested_at DESC);

-- Query pattern: site-scoped listings.
CREATE INDEX IF NOT EXISTS idx_reports_site_id
    ON reports (site_id)
    WHERE site_id <> '';

COMMIT;
