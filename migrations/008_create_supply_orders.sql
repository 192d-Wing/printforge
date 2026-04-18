-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 008: Create supply_reorders and supply_approvals tables
-- NIST 800-53 Rev 5: AC-3 — Access Enforcement (approval authority)
-- NIST 800-53 Rev 5: AU-12 — Audit Record Generation
--
-- Tracks supply reorder requests triggered by threshold or predictive
-- depletion detection, and the multi-level approval workflow.

BEGIN;

-- ── Supply reorder requests ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS supply_reorders (
    id                  UUID        PRIMARY KEY,
    printer_id          TEXT        NOT NULL REFERENCES printers (id),
    consumable_kind     TEXT        NOT NULL,
    current_level_pct   SMALLINT    NOT NULL CHECK (current_level_pct >= 0 AND current_level_pct <= 100),
    trigger_type        TEXT        NOT NULL
                                    CHECK (trigger_type IN ('Threshold', 'Predictive')),
    status              TEXT        NOT NULL DEFAULT 'PendingApproval'
                                    CHECK (status IN (
                                        'PendingApproval', 'Approved', 'Submitted',
                                        'Fulfilled', 'Cancelled'
                                    )),
    estimated_cost_cents BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at         TIMESTAMPTZ,
    submitted_at        TIMESTAMPTZ
);

-- Query pattern: find pending orders for a specific printer.
CREATE INDEX IF NOT EXISTS idx_supply_reorders_printer ON supply_reorders (printer_id);

-- Query pattern: find orders by status (approval queue).
CREATE INDEX IF NOT EXISTS idx_supply_reorders_status ON supply_reorders (status);

-- Query pattern: time-range reporting.
CREATE INDEX IF NOT EXISTS idx_supply_reorders_created_at ON supply_reorders (created_at DESC);

-- ── Supply approval records ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS supply_approvals (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    reorder_id          UUID        NOT NULL REFERENCES supply_reorders (id),
    approver_edipi      TEXT        NOT NULL,
    level               TEXT        NOT NULL
                                    CHECK (level IN ('Auto', 'SiteAdmin', 'FleetAdmin')),
    decision            TEXT        NOT NULL
                                    CHECK (decision IN ('Approved', 'Rejected')),
    reason              TEXT,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Query pattern: find approval history for a reorder.
CREATE INDEX IF NOT EXISTS idx_supply_approvals_reorder ON supply_approvals (reorder_id);

-- Query pattern: find approvals by approver (audit trail).
CREATE INDEX IF NOT EXISTS idx_supply_approvals_approver ON supply_approvals (approver_edipi);

COMMIT;
