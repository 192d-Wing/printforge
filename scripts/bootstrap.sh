#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors
#
# bootstrap.sh — Generate Cargo.toml and src/lib.rs for all crates
# Run once after extracting the scaffold archive.

set -euo pipefail

CRATES=(
  "pf-common:Shared types, error handling, crypto, config"
  "pf-auth:Identity and authentication service"
  "pf-job-queue:Print job lifecycle management"
  "pf-fleet-mgr:Printer fleet management and monitoring"
  "pf-firmware-mgr:Firmware lifecycle management"
  "pf-policy-engine:OPA/Rego print policy evaluation"
  "pf-accounting:Print cost accounting and chargeback"
  "pf-supply:Supply chain automation"
  "pf-audit:Immutable audit log and compliance evidence"
  "pf-spool:Encrypted spool store via RustFS S3"
  "pf-api-gateway:HTTP/gRPC API gateway"
  "pf-admin-ui:Admin dashboard backend"
  "pf-enroll-portal:Self-service enrollment portal"
  "pf-cache-node:Installation-level edge cache orchestrator"
  "pf-driver-service:IPPS endpoint for workstation drivers"
  "pf-user-provisioning:JIT provisioning and SCIM 2.0"
)

echo "▸ Bootstrapping PrintForge crates..."
echo ""

for entry in "${CRATES[@]}"; do
  IFS=: read -r name desc <<< "$entry"
  dir="crates/${name}"

  # Skip if Cargo.toml already exists
  if [[ -f "${dir}/Cargo.toml" ]]; then
    echo "  ○ ${name} — already exists, skipping"
    continue
  fi

  mkdir -p "${dir}/src"
  mkdir -p "${dir}/tests"

  # ─── Cargo.toml ───────────────────────────────────────────────────────────
  cat > "${dir}/Cargo.toml" << EOF
[package]
name = "${name}"
description = "${desc}"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish.workspace = true

[dependencies]
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
uuid = { workspace = true }
chrono = { workspace = true }

[dev-dependencies]
tokio-test = { workspace = true }
proptest = { workspace = true }

[lints]
workspace = true
EOF

  # Add pf-common dependency for all crates except pf-common itself
  if [[ "${name}" != "pf-common" ]]; then
    # Insert after [dependencies] line
    sed -i '' '/^\[dependencies\]$/a\
pf-common = { path = "../pf-common" }' "${dir}/Cargo.toml"
  fi

  # ─── Add crate-specific dependencies ────────────────────────────────────
  case "${name}" in
    pf-common)
      cat >> "${dir}/Cargo.toml" << 'EOF'
secrecy = { workspace = true }
ring = { workspace = true }
EOF
      ;;
    pf-auth)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# Auth-specific
openidconnect = { workspace = true }
jsonwebtoken = { workspace = true }
x509-parser = { workspace = true }
ring = { workspace = true }
secrecy = { workspace = true }
lru = "0.12"
EOF
      ;;
    pf-spool)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# S3 / RustFS
aws-sdk-s3 = { workspace = true }
aws-config = { workspace = true }
ring = { workspace = true }
secrecy = { workspace = true }
bytes = { workspace = true }
EOF
      ;;
    pf-job-queue)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# Job queue specific
sqlx = { workspace = true }
async-nats = { workspace = true }
bytes = { workspace = true }
EOF
      ;;
    pf-api-gateway)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# HTTP framework
axum = { workspace = true }
axum-extra = { workspace = true }
tower = { workspace = true }
tower-http = { workspace = true }
hyper = { workspace = true }
rustls = { workspace = true }
EOF
      ;;
    pf-fleet-mgr)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# Fleet management
sqlx = { workspace = true }
EOF
      ;;
    pf-audit)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# Audit
sqlx = { workspace = true }
tracing-subscriber = { workspace = true }
tracing-opentelemetry = { workspace = true }
opentelemetry = { workspace = true }
EOF
      ;;
    pf-cache-node)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# Embedded services
pf-auth = { path = "../pf-auth" }
pf-job-queue = { path = "../pf-job-queue" }
pf-spool = { path = "../pf-spool" }
pf-fleet-mgr = { path = "../pf-fleet-mgr" }
pf-driver-service = { path = "../pf-driver-service" }
async-nats = { workspace = true }
EOF
      ;;
    pf-user-provisioning)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# User provisioning
sqlx = { workspace = true }
pf-auth = { path = "../pf-auth" }
EOF
      ;;
    pf-enroll-portal)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# Enrollment
axum = { workspace = true }
pf-auth = { path = "../pf-auth" }
pf-user-provisioning = { path = "../pf-user-provisioning" }
EOF
      ;;
    pf-driver-service)
      cat >> "${dir}/Cargo.toml" << 'EOF'

# IPPS server
rustls = { workspace = true }
bytes = { workspace = true }
pf-job-queue = { path = "../pf-job-queue" }
EOF
      ;;
    pf-accounting|pf-supply|pf-firmware-mgr)
      cat >> "${dir}/Cargo.toml" << 'EOF'

sqlx = { workspace = true }
EOF
      ;;
    pf-policy-engine)
      cat >> "${dir}/Cargo.toml" << 'EOF'

sqlx = { workspace = true }
EOF
      ;;
    pf-admin-ui)
      cat >> "${dir}/Cargo.toml" << 'EOF'

axum = { workspace = true }
EOF
      ;;
  esac

  # ─── src/lib.rs ───────────────────────────────────────────────────────────
  cat > "${dir}/src/lib.rs" << EOF
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! ${desc}

#![forbid(unsafe_code)]
EOF

  # ─── src/error.rs ─────────────────────────────────────────────────────────
  CRATE_PREFIX=$(echo "${name}" | sed 's/pf-//' | sed 's/-/_/g' | sed 's/.*/\u&/' | sed 's/_\(.\)/\U\1/g')
  cat > "${dir}/src/error.rs" << EOF
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for ${name}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ${CRATE_PREFIX}Error {
    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}
EOF

  echo "  ✓ ${name}"
done

echo ""
echo "▸ Verifying workspace compiles..."
if cargo check --workspace 2>&1; then
  echo ""
  echo "✓ All 16 crates compile successfully."
else
  echo ""
  echo "⚠ Compilation issues found. This may be expected if workspace"
  echo "  dependencies need version resolution. Run 'cargo check --workspace'"
  echo "  manually to see details."
fi

echo ""
echo "▸ Next steps:"
echo "  1. git add -A"
echo "  2. git commit -m 'chore(workspace): bootstrap all crate Cargo.toml and lib.rs'"
echo "  3. Start implementing pf-common (see GETTING_STARTED.md Step 5)"
