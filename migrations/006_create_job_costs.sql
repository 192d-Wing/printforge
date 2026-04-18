-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 006: Create job_costs table
-- NIST 800-53 Rev 5: AU-12 — Audit Record Generation
--
-- Stores per-job cost breakdowns for chargeback reporting. Costs are
-- tracked in US cents (integer arithmetic) to avoid floating-point
-- rounding issues. Both estimated (at submission) and final (at completion)
-- cost records may exist for the same job.

BEGIN;

CREATE TABLE IF NOT EXISTS job_costs (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id                  UUID        NOT NULL REFERENCES jobs (id),
    cost_center_code        TEXT        NOT NULL,
    cost_center_name        TEXT        NOT NULL,
    total_impressions       INTEGER     NOT NULL DEFAULT 0,
    total_cost_cents        BIGINT      NOT NULL DEFAULT 0,
    base_cost_cents         BIGINT      NOT NULL DEFAULT 0,
    color_surcharge_cents   BIGINT      NOT NULL DEFAULT 0,
    media_surcharge_cents   BIGINT      NOT NULL DEFAULT 0,
    finishing_surcharge_cents BIGINT    NOT NULL DEFAULT 0,
    duplex_discount_cents   BIGINT      NOT NULL DEFAULT 0,
    is_estimate             BOOLEAN     NOT NULL DEFAULT TRUE,
    calculated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Costs must be non-negative.
    CHECK (total_cost_cents >= 0),
    CHECK (base_cost_cents >= 0),
    CHECK (color_surcharge_cents >= 0),
    CHECK (media_surcharge_cents >= 0),
    CHECK (finishing_surcharge_cents >= 0),
    CHECK (duplex_discount_cents >= 0),

    -- The application uses ON CONFLICT (job_id) for upsert.
    CONSTRAINT uq_job_costs_job_id UNIQUE (job_id)
);

-- Query pattern: look up cost for a specific job.
CREATE INDEX IF NOT EXISTS idx_job_costs_job_id ON job_costs (job_id);

-- Query pattern: chargeback reports by cost center within a date range.
CREATE INDEX IF NOT EXISTS idx_job_costs_cost_center_calculated ON job_costs (cost_center_code, calculated_at DESC);

-- Query pattern: distinguish estimates from final costs.
CREATE INDEX IF NOT EXISTS idx_job_costs_is_estimate ON job_costs (is_estimate) WHERE is_estimate = FALSE;

COMMIT;
