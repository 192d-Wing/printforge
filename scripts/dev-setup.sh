#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# ---------------------------------------------------------------------------
# PrintForge Development Environment Setup
#
# Starts all infrastructure containers, runs database migrations, creates
# the RustFS spool bucket, and verifies connectivity.
#
# Usage:
#   ./scripts/dev-setup.sh          # full setup
#   ./scripts/dev-setup.sh --up     # just start containers
#   ./scripts/dev-setup.sh --migrate # just run migrations
#   ./scripts/dev-setup.sh --status  # check service health
#   ./scripts/dev-setup.sh --down    # tear down
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/deploy/docker-compose.dev.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
check_deps() {
    local missing=0
    for cmd in docker psql; do
        if ! command -v "$cmd" &>/dev/null; then
            fail "Required command not found: $cmd"
            missing=1
        fi
    done
    if ! docker compose version &>/dev/null 2>&1; then
        fail "docker compose (v2) not found"
        missing=1
    fi
    if [[ $missing -eq 1 ]]; then
        echo "Install missing dependencies and retry."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Start containers
# ---------------------------------------------------------------------------
start_containers() {
    info "Starting infrastructure containers..."
    docker compose -f "$COMPOSE_FILE" up -d

    info "Waiting for PostgreSQL..."
    for i in $(seq 1 30); do
        if docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U printforge -d printforge &>/dev/null; then
            ok "PostgreSQL is ready"
            break
        fi
        if [[ $i -eq 30 ]]; then
            fail "PostgreSQL did not become ready in time"
            exit 1
        fi
        sleep 1
    done

    info "Waiting for NATS..."
    for i in $(seq 1 20); do
        if curl -sf http://localhost:8222/varz &>/dev/null; then
            ok "NATS is ready"
            break
        fi
        if [[ $i -eq 20 ]]; then
            fail "NATS did not become ready in time"
            exit 1
        fi
        sleep 1
    done

    info "Waiting for Keycloak..."
    for i in $(seq 1 60); do
        if curl -sf http://localhost:8180/health/ready 2>/dev/null | grep -q '"status":"UP"'; then
            ok "Keycloak is ready"
            break
        fi
        if [[ $i -eq 60 ]]; then
            warn "Keycloak not ready yet — it may still be importing the realm. Check: http://localhost:8180"
        fi
        sleep 2
    done
}

# ---------------------------------------------------------------------------
# Run database migrations
# ---------------------------------------------------------------------------
run_migrations() {
    info "Running database migrations..."
    export PGPASSWORD="printforge-dev-only"

    for migration in "$PROJECT_ROOT"/migrations/*.sql; do
        local name
        name=$(basename "$migration")
        info "  Applying $name..."
        psql -h localhost -p 5432 -U printforge -d printforge -f "$migration" -v ON_ERROR_STOP=1 2>&1 | \
            grep -v "^$" | sed 's/^/    /' || true
    done

    ok "All migrations applied"
    unset PGPASSWORD
}

# ---------------------------------------------------------------------------
# Seed test data
# ---------------------------------------------------------------------------
seed_data() {
    info "Seeding test data..."
    export PGPASSWORD="printforge-dev-only"

    psql -h localhost -p 5432 -U printforge -d printforge -v ON_ERROR_STOP=1 <<'EOF'
-- Test users (matching Keycloak realm users)
INSERT INTO users (id, edipi, display_name, organization, roles_json, preferences_json, status, provisioning_source, created_at, updated_at)
VALUES
    (gen_random_uuid(), '1234567890', 'DOE.JOHN.Q.1234567890', 'Test Unit, Langley AFB',
     '["User"]',
     '{"default_color_mode":"grayscale","default_duplex":true,"default_media_size":"letter"}',
     'Active', 'Jit', now(), now()),
    (gen_random_uuid(), '0987654321', 'SMITH.JANE.A.0987654321', 'Test Unit, Langley AFB',
     '[{"SiteAdmin":"LANGLEY"}]',
     '{"default_color_mode":"grayscale","default_duplex":true,"default_media_size":"letter"}',
     'Active', 'Jit', now(), now()),
    (gen_random_uuid(), '1111111111', 'ADMIN.FLEET.X.1111111111', 'HQ, Pentagon',
     '["FleetAdmin", "Auditor"]',
     '{"default_color_mode":"grayscale","default_duplex":true,"default_media_size":"letter"}',
     'Active', 'Jit', now(), now())
ON CONFLICT DO NOTHING;

-- Test printers
INSERT INTO printers (id, vendor, model, serial_number, ip_address,
    location_installation, location_building, location_floor, location_room,
    status, firmware_version, discovery_method)
VALUES
    ('PRN-0001', 'HP', 'LaserJet Enterprise M609', 'SN-HP-001',
     '10.0.1.42', 'Langley AFB', 'Building 100', '2', 'Room 201',
     'Online', '4.11.2.1', 'Manual'),
    ('PRN-0002', 'Xerox', 'VersaLink C405', 'SN-XRX-002',
     '10.0.1.43', 'Langley AFB', 'Building 100', '1', 'Room 105',
     'Online', '73.10.21', 'Manual')
ON CONFLICT DO NOTHING;

-- Test quota counters
INSERT INTO quota_counters (edipi, page_limit, pages_used, color_page_limit, color_pages_used,
    burst_pages_used, period_start, period_end)
VALUES
    ('1234567890', 500, 42, 50, 5, 0, date_trunc('month', now()), date_trunc('month', now()) + interval '1 month'),
    ('0987654321', 500, 100, 50, 20, 0, date_trunc('month', now()), date_trunc('month', now()) + interval '1 month')
ON CONFLICT DO NOTHING;
EOF

    ok "Test data seeded"
    unset PGPASSWORD
}

# ---------------------------------------------------------------------------
# Status check
# ---------------------------------------------------------------------------
check_status() {
    echo ""
    echo "============================================"
    echo "  PrintForge Dev Environment Status"
    echo "============================================"
    echo ""

    # PostgreSQL
    if pg_isready -h localhost -p 5432 -U printforge &>/dev/null; then
        ok "PostgreSQL    :5432  (printforge/printforge/printforge-dev-only)"
    else
        fail "PostgreSQL    :5432  NOT READY"
    fi

    # NATS
    if curl -sf http://localhost:8222/varz &>/dev/null; then
        ok "NATS          :4222  (client), :8222 (monitoring)"
    else
        fail "NATS          :4222  NOT READY"
    fi

    # RustFS
    if curl -sf http://localhost:9000/minio/health/live &>/dev/null; then
        ok "RustFS        :9000  (S3 API), :9001 (console)"
    else
        warn "RustFS        :9000  NOT READY (may not be running)"
    fi

    # Keycloak
    if curl -sf http://localhost:8180/health/ready 2>/dev/null | grep -q '"status":"UP"'; then
        ok "Keycloak      :8180  (admin: admin/admin)"
        echo ""
        info "OIDC Discovery:"
        echo "  http://localhost:8180/realms/printforge/.well-known/openid-configuration"
        echo ""
        info "Test Users (password: testpass123):"
        echo "  DOE.JOHN.Q.1234567890     — User"
        echo "  SMITH.JANE.A.0987654321   — SiteAdmin (Langley)"
        echo "  ADMIN.FLEET.X.1111111111  — FleetAdmin + Auditor"
    else
        fail "Keycloak      :8180  NOT READY"
    fi

    echo ""

    # DB table check
    export PGPASSWORD="printforge-dev-only"
    local table_count
    table_count=$(psql -h localhost -p 5432 -U printforge -d printforge -t -c \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'" 2>/dev/null | tr -d ' ')
    if [[ -n "$table_count" && "$table_count" -gt 0 ]]; then
        ok "Database has $table_count tables"
    else
        warn "Database has no tables — run: ./scripts/dev-setup.sh --migrate"
    fi
    unset PGPASSWORD

    echo ""
    echo "============================================"
    echo "  Environment variables for PrintForge:"
    echo "============================================"
    echo ""
    echo "  export PF_DB_HOST=localhost"
    echo "  export PF_DB_PORT=5432"
    echo "  export PF_DB_NAME=printforge"
    echo "  export PF_DB_USER=printforge"
    echo "  export PF_DB_PASSWORD=printforge-dev-only"
    echo "  export PF_NATS_URL=nats://localhost:4222"
    echo "  export PF_AUTH_OIDC_ISSUER_URL=http://localhost:8180/realms/printforge"
    echo "  export PF_AUTH_OIDC_CLIENT_ID=printforge-api"
    echo "  export RUST_LOG=info"
    echo ""
}

# ---------------------------------------------------------------------------
# Tear down
# ---------------------------------------------------------------------------
tear_down() {
    info "Stopping and removing containers..."
    docker compose -f "$COMPOSE_FILE" down -v
    ok "Environment torn down"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_deps

    case "${1:-}" in
        --up)
            start_containers
            ;;
        --migrate)
            run_migrations
            ;;
        --seed)
            seed_data
            ;;
        --status)
            check_status
            ;;
        --down)
            tear_down
            ;;
        *)
            # Full setup
            start_containers
            run_migrations
            seed_data
            check_status
            ;;
    esac
}

main "$@"
