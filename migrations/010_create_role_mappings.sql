-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 010: Create role_mappings table
-- NIST 800-53 Rev 5: AC-2 — Account Management
--
-- Stores IdP group to PrintForge role mapping rules configured by Fleet
-- Administrators. Supports wildcard patterns (trailing *) for site-scoped
-- roles (e.g., "PrintForge-SiteAdmin-*" -> SiteAdmin). Rules are evaluated
-- in priority order on every user login.

BEGIN;

CREATE TABLE IF NOT EXISTS role_mappings (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    group_pattern       TEXT        NOT NULL,
    target_role         TEXT        NOT NULL,
    priority            INTEGER     NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each group pattern should appear only once.
    CONSTRAINT uq_role_mappings_group_pattern UNIQUE (group_pattern)
);

-- Query pattern: load all rules ordered by priority for evaluation.
CREATE INDEX IF NOT EXISTS idx_role_mappings_priority ON role_mappings (priority ASC);

COMMIT;
