-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 014: Add target_printer_id to jobs
-- NIST 800-53 Rev 5: AU-2 — Event Logging
--
-- Captures which printer a job was released to. NULL while the job is
-- Held (no release decision yet) and for jobs that ended in Purged
-- without being routed. Set at the Held -> Waiting transition by the
-- service's release path.

BEGIN;

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS target_printer_id TEXT REFERENCES printers (id);

-- Query pattern: per-printer job history.
CREATE INDEX IF NOT EXISTS idx_jobs_target_printer_id
    ON jobs (target_printer_id)
    WHERE target_printer_id IS NOT NULL;

COMMIT;
