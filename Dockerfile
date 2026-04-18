# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# ---------------------------------------------------------------------------
# Stage 1: Build all workspace binaries
# ---------------------------------------------------------------------------
FROM rust:1.85-bookworm AS builder

WORKDIR /src

# Cache dependency builds: copy manifests first, create stub lib/main files,
# then run cargo build to cache the dependency layer.
COPY Cargo.toml Cargo.lock ./
COPY crates/pf-common/Cargo.toml              crates/pf-common/Cargo.toml
COPY crates/pf-auth/Cargo.toml                crates/pf-auth/Cargo.toml
COPY crates/pf-job-queue/Cargo.toml           crates/pf-job-queue/Cargo.toml
COPY crates/pf-fleet-mgr/Cargo.toml           crates/pf-fleet-mgr/Cargo.toml
COPY crates/pf-firmware-mgr/Cargo.toml        crates/pf-firmware-mgr/Cargo.toml
COPY crates/pf-policy-engine/Cargo.toml       crates/pf-policy-engine/Cargo.toml
COPY crates/pf-accounting/Cargo.toml          crates/pf-accounting/Cargo.toml
COPY crates/pf-supply/Cargo.toml              crates/pf-supply/Cargo.toml
COPY crates/pf-audit/Cargo.toml               crates/pf-audit/Cargo.toml
COPY crates/pf-spool/Cargo.toml               crates/pf-spool/Cargo.toml
COPY crates/pf-api-gateway/Cargo.toml         crates/pf-api-gateway/Cargo.toml
COPY crates/pf-admin-ui/Cargo.toml            crates/pf-admin-ui/Cargo.toml
COPY crates/pf-enroll-portal/Cargo.toml       crates/pf-enroll-portal/Cargo.toml
COPY crates/pf-cache-node/Cargo.toml          crates/pf-cache-node/Cargo.toml
COPY crates/pf-driver-service/Cargo.toml      crates/pf-driver-service/Cargo.toml
COPY crates/pf-user-provisioning/Cargo.toml   crates/pf-user-provisioning/Cargo.toml

# Create stub source files so cargo can resolve the workspace and cache deps.
RUN set -eux; \
    for crate_dir in crates/*/; do \
        mkdir -p "${crate_dir}src"; \
        echo '// stub' > "${crate_dir}src/lib.rs"; \
        if grep -q '\[\[bin\]\]' "${crate_dir}Cargo.toml" 2>/dev/null; then \
            echo 'fn main() {}' > "${crate_dir}src/main.rs"; \
        fi; \
    done

RUN cargo build --release --workspace 2>&1 || true

# Copy real source and rebuild.
COPY crates/ crates/
RUN cargo build --release --workspace

# ---------------------------------------------------------------------------
# Stage 2: Minimal runtime image
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12 AS runtime

LABEL org.opencontainers.image.source="https://github.com/printforge/printforge" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="PrintForge"

COPY --from=builder /src/target/release/pf-api-gateway /usr/local/bin/pf-api-gateway
COPY --from=builder /src/target/release/pf-cache-node  /usr/local/bin/pf-cache-node

# Run as non-root (distroless nonroot user uid=65534).
USER 65534:65534

ENTRYPOINT ["pf-api-gateway"]
