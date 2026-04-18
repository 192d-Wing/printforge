-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 PrintForge Contributors

-- Migration 002: Create printers table
-- NIST 800-53 Rev 5: CM-8 — System Component Inventory
--
-- Maintains a comprehensive inventory of all managed printers including
-- hardware details, firmware versions, network addresses, and physical
-- locations. Printer IDs follow the PRN-XXXX format.

BEGIN;

CREATE TABLE IF NOT EXISTS printers (
    id                      TEXT        PRIMARY KEY CHECK (id ~ '^PRN-.+'),
    vendor                  TEXT        NOT NULL,
    model                   TEXT        NOT NULL,
    serial_number           TEXT        NOT NULL,
    firmware_version        TEXT        NOT NULL,
    ip_address              INET        NOT NULL,
    hostname                TEXT,
    location_installation   TEXT        NOT NULL DEFAULT '',
    location_building       TEXT        NOT NULL DEFAULT '',
    location_floor          TEXT        NOT NULL DEFAULT '',
    location_room           TEXT        NOT NULL DEFAULT '',
    discovery_method        TEXT        NOT NULL DEFAULT 'Manual'
                                        CHECK (discovery_method IN ('SnmpV3Walk', 'DnsSd', 'Manual')),
    status                  TEXT        NOT NULL DEFAULT 'Offline'
                                        CHECK (status IN ('Online', 'Offline', 'Error', 'Maintenance', 'Printing')),
    toner_k                 SMALLINT    CHECK (toner_k IS NULL OR (toner_k >= 0 AND toner_k <= 100)),
    toner_c                 SMALLINT    CHECK (toner_c IS NULL OR (toner_c >= 0 AND toner_c <= 100)),
    toner_m                 SMALLINT    CHECK (toner_m IS NULL OR (toner_m >= 0 AND toner_m <= 100)),
    toner_y                 SMALLINT    CHECK (toner_y IS NULL OR (toner_y >= 0 AND toner_y <= 100)),
    paper                   SMALLINT    CHECK (paper IS NULL OR (paper >= 0 AND paper <= 100)),
    health_score            SMALLINT    CHECK (health_score IS NULL OR (health_score >= 0 AND health_score <= 100)),
    total_page_count        BIGINT,
    registered_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_polled_at          TIMESTAMPTZ,
    consecutive_poll_failures INTEGER   NOT NULL DEFAULT 0
);

-- Query pattern: filter printers by operational status.
CREATE INDEX IF NOT EXISTS idx_printers_status ON printers (status);

-- Query pattern: filter printers by vendor/model for firmware management.
CREATE INDEX IF NOT EXISTS idx_printers_vendor_model ON printers (vendor, model);

-- Query pattern: find printers by installation/building.
CREATE INDEX IF NOT EXISTS idx_printers_location_installation ON printers (location_installation);
CREATE INDEX IF NOT EXISTS idx_printers_location_building ON printers (location_building);

-- Query pattern: find printers with low health scores for alerting.
CREATE INDEX IF NOT EXISTS idx_printers_health_score ON printers (health_score) WHERE health_score IS NOT NULL;

-- Unique serial number per vendor (prevent duplicate registrations).
CREATE UNIQUE INDEX IF NOT EXISTS idx_printers_serial_number ON printers (vendor, serial_number);

COMMIT;
