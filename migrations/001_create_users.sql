-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 001: Create users table
-- NIST 800-53 Rev 5: AC-2 — Account Management
--
-- Stores provisioned user accounts. Users are created via JIT provisioning
-- or SCIM 2.0. User records are never hard-deleted; deactivation sets
-- status to 'Suspended' to preserve audit trail integrity.

BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id                  UUID        PRIMARY KEY,
    edipi               TEXT        NOT NULL,
    display_name        TEXT        NOT NULL,
    organization        TEXT        NOT NULL,
    roles_json          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    cost_centers_json   JSONB       NOT NULL DEFAULT '[]'::jsonb,
    preferences_json    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    status              TEXT        NOT NULL DEFAULT 'Active'
                                    CHECK (status IN ('Active', 'Suspended')),
    provisioning_source TEXT        NOT NULL
                                    CHECK (provisioning_source IN ('Jit', 'Scim', 'AttributeSync')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ
);

-- EDIPI must be unique across all users (NIST SI-10 validated 10-digit identifier).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_edipi ON users (edipi);

-- Query pattern: list users by status (e.g., find all suspended accounts).
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);

-- Query pattern: find users by provisioning source.
CREATE INDEX IF NOT EXISTS idx_users_provisioning_source ON users (provisioning_source);

-- Query pattern: find users by organization.
CREATE INDEX IF NOT EXISTS idx_users_organization ON users (organization);

COMMIT;
