-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 007: Create firmware_artifacts and firmware_deployments tables
-- NIST 800-53 Rev 5: SI-2 — Flaw Remediation
-- NIST 800-53 Rev 5: SI-7 — Software/Firmware Integrity
-- NIST 800-53 Rev 5: CM-3 — Configuration Change Control
--
-- Tracks firmware artifact metadata (checksums, signatures) and phased
-- deployment history (canary -> staging -> fleet) with rollback records.

BEGIN;

-- ── Firmware artifacts (validated binaries in the OCI registry) ────────

CREATE TABLE IF NOT EXISTS firmware_artifacts (
    id                  UUID        PRIMARY KEY,
    vendor              TEXT        NOT NULL,
    model               TEXT        NOT NULL,
    version             TEXT        NOT NULL,
    checksum_sha256     TEXT        NOT NULL,
    size_bytes          BIGINT      NOT NULL DEFAULT 0,
    signature_info      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    acquired_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    validated_at        TIMESTAMPTZ,

    -- Same vendor + model + version should not be registered twice.
    CONSTRAINT uq_firmware_vendor_model_version UNIQUE (vendor, model, version)
);

-- Query pattern: list firmware versions for a specific printer model.
CREATE INDEX IF NOT EXISTS idx_firmware_artifacts_vendor_model ON firmware_artifacts (vendor, model);

-- Query pattern: find unvalidated firmware artifacts.
CREATE INDEX IF NOT EXISTS idx_firmware_artifacts_unvalidated ON firmware_artifacts (acquired_at)
    WHERE validated_at IS NULL;

-- ── Firmware deployments (phased rollout tracking) ─────────────────────

CREATE TABLE IF NOT EXISTS firmware_deployments (
    id                  UUID        PRIMARY KEY,
    artifact_id         UUID        NOT NULL REFERENCES firmware_artifacts (id),
    printer_id          TEXT        NOT NULL REFERENCES printers (id),
    status              TEXT        NOT NULL DEFAULT 'Pending'
                                    CHECK (status IN (
                                        'Pending', 'InProgress', 'Soaking', 'Halted',
                                        'Completed', 'RolledBack', 'Cancelled'
                                    )),
    phase               TEXT        NOT NULL DEFAULT 'Canary'
                                    CHECK (phase IN ('Canary', 'Staging', 'Fleet')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    soak_started_at     TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ
);

-- Query pattern: find active deployments for a printer.
CREATE INDEX IF NOT EXISTS idx_firmware_deployments_printer ON firmware_deployments (printer_id);

-- Query pattern: find deployments by artifact (rollout progress tracking).
CREATE INDEX IF NOT EXISTS idx_firmware_deployments_artifact ON firmware_deployments (artifact_id);

-- Query pattern: find active/in-progress deployments.
CREATE INDEX IF NOT EXISTS idx_firmware_deployments_status ON firmware_deployments (status)
    WHERE status IN ('Pending', 'InProgress', 'Soaking');

COMMIT;
