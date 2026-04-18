-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 011: Add site_id to users
-- NIST 800-53 Rev 5: AC-3 — Access Enforcement
--
-- Introduces a per-user site attribution populated from the identity
-- provider's `site` (or `site_id`) claim during JIT provisioning and
-- attribute sync. Downstream queries (admin-ui job listings, dashboard
-- KPIs) use this column to translate a Site Admin's scope into a row
-- filter.
--
-- Existing rows keep the default empty string, meaning "unattributed" —
-- such users are visible only to a Fleet Admin until the claim is
-- populated on their next login.

BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS site_id TEXT NOT NULL DEFAULT '';

-- Query pattern: list users by site (admin dashboard, scoped queries).
-- Partial index so the common unattributed rows don't bloat the index.
CREATE INDEX IF NOT EXISTS idx_users_site_id
    ON users (site_id)
    WHERE site_id <> '';

COMMIT;
