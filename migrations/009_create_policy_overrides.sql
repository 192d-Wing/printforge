-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 009: Create policy_overrides table
-- NIST 800-53 Rev 5: AC-3 — Access Enforcement
--
-- Stores per-cost-center policy overrides that modify default print behavior.
-- For example, a cost center can force all jobs to duplex or grayscale to
-- reduce printing costs. These overrides are evaluated by pf-policy-engine
-- before job acceptance.

BEGIN;

CREATE TABLE IF NOT EXISTS policy_overrides (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cost_center_code    TEXT        NOT NULL,
    force_duplex        BOOLEAN     NOT NULL DEFAULT FALSE,
    force_grayscale     BOOLEAN     NOT NULL DEFAULT FALSE,
    max_page_limit      INTEGER,
    max_copies          INTEGER,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One override set per cost center.
    CONSTRAINT uq_policy_overrides_cost_center UNIQUE (cost_center_code)
);

-- Query pattern: look up overrides by cost center code.
CREATE INDEX IF NOT EXISTS idx_policy_overrides_cost_center ON policy_overrides (cost_center_code);

COMMIT;
