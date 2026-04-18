# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# PrintForge — Getting Started

This guide takes you from extracting the scaffold archive to having multiple Claude Code
agents working in parallel on different crates.

---

## Prerequisites

Install these before starting:

```bash
# Rust toolchain (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup component add rustfmt clippy

# Cargo tools
cargo install cargo-nextest    # Fast test runner
cargo install cargo-deny       # License + advisory enforcement
cargo install cargo-audit      # RustSec vulnerability scanner
cargo install cargo-cyclonedx  # SBOM generation

# Node.js (for commitlint — optional but recommended)
npm install -g @commitlint/cli @commitlint/config-conventional

# Claude Code CLI
npm install -g @anthropic-ai/claude-code
```

---

## Step 1: Extract and Initialize

```bash
# Extract the scaffold
tar xzf printforge-claude-code-scaffold.tar.gz
cd printforge

# Initialize git
git init
git add -A
git commit -m "chore(workspace): initial scaffold with 16-crate workspace"
```

---

## Step 2: Bootstrap Crate Cargo.toml Files

The scaffold includes `CLAUDE.md` files and the workspace `Cargo.toml`, but each crate
needs its own `Cargo.toml` and `src/lib.rs` to compile. Run this bootstrap script:

```bash
#!/usr/bin/env bash
# Save as scripts/bootstrap.sh and run it once

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

for entry in "${CRATES[@]}"; do
  IFS=: read -r name desc <<< "$entry"
  dir="crates/${name}"
  
  # Skip if Cargo.toml already exists
  [[ -f "${dir}/Cargo.toml" ]] && continue

  mkdir -p "${dir}/src"

  # Create Cargo.toml
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
tracing = { workspace = true }
thiserror = { workspace = true }

[lints]
workspace = true
EOF

  # Add pf-common dependency for all crates except pf-common itself
  if [[ "${name}" != "pf-common" ]]; then
    sed -i '/\[dependencies\]/a pf-common = { path = "../pf-common" }' "${dir}/Cargo.toml"
  fi

  # Create lib.rs with SPDX header and forbid(unsafe_code)
  cat > "${dir}/src/lib.rs" << EOF
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! ${desc}

#![forbid(unsafe_code)]
EOF

  echo "✓ Bootstrapped ${name}"
done

echo ""
echo "All crates bootstrapped. Run 'cargo check --workspace' to verify."
```

Run it:

```bash
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

---

## Step 3: Verify the Workspace Builds

```bash
# Check that all 16 crates compile
cargo check --workspace

# Run the (empty) test suite
cargo nextest run --workspace

# Verify license policy
cargo deny check licenses

# Verify no vulnerabilities
cargo audit

# You should see all green. Commit the bootstrap:
git add -A
git commit -m "chore(workspace): bootstrap all crate Cargo.toml and lib.rs files"
```

---

## Step 4: Set Up Remote (Optional but Recommended)

If you're using GitHub/GitLab, push the repo so worktree agents can push branches:

```bash
git remote add origin git@github.com:your-org/printforge.git
git push -u origin main
```

---

## Step 5: Start with pf-common (Sequential — Do This First)

`pf-common` is the foundation. Every other crate depends on it. Build shared types
before launching parallel agents:

```bash
# Option A: Work directly on main (small team / solo)
claude

# In the Claude Code session, say:
# "Read CLAUDE.md and crates/pf-common/CLAUDE.md, then implement the shared types
#  in pf-common: identity.rs, job.rs, fleet.rs, policy.rs, audit.rs, crypto.rs,
#  error.rs, validated.rs, config.rs, and time.rs"
```

Or use the worktree script:

```bash
./scripts/worktree-agent.sh pf-common PF-001

# The agent will:
# 1. Create .worktrees/pf-common on branch feat/pf-common/PF-001
# 2. Launch Claude Code in that directory
# 3. Read both CLAUDE.md files
# 4. Implement the shared types
```

After the agent finishes, merge `pf-common` to main:

```bash
# If using worktree:
git merge feat/pf-common/PF-001
git push origin main

# Clean up the worktree:
git worktree remove .worktrees/pf-common
```

---

## Step 6: Launch Parallel Agents

Once `pf-common` is merged to main, launch agents in parallel by group.
Open separate terminal windows/tabs for each:

### Wave 1 — Core Services (5 agents in parallel)

```bash
# Terminal 1: Identity
./scripts/worktree-agent.sh pf-auth PF-010

# Terminal 2: Print pipeline
./scripts/worktree-agent.sh pf-spool PF-020

# Terminal 3: Fleet
./scripts/worktree-agent.sh pf-fleet-mgr PF-030

# Terminal 4: Policy
./scripts/worktree-agent.sh pf-policy-engine PF-040

# Terminal 5: Audit
./scripts/worktree-agent.sh pf-audit PF-050
```

Each agent works in isolation. They share `pf-common` types (read-only from their
perspective) and cannot modify each other's crates.

### Wave 2 — Dependent Services (after Wave 1 merges)

```bash
# These depend on Wave 1 crates:
./scripts/worktree-agent.sh pf-job-queue PF-060        # needs pf-spool, pf-auth, pf-policy-engine
./scripts/worktree-agent.sh pf-user-provisioning PF-070 # needs pf-auth
./scripts/worktree-agent.sh pf-accounting PF-080        # needs pf-policy-engine
./scripts/worktree-agent.sh pf-firmware-mgr PF-090      # needs pf-fleet-mgr
./scripts/worktree-agent.sh pf-supply PF-100            # needs pf-fleet-mgr
./scripts/worktree-agent.sh pf-driver-service PF-110    # needs pf-job-queue, pf-spool
```

### Wave 3 — Integration Layer (after Wave 2 merges)

```bash
./scripts/worktree-agent.sh pf-api-gateway PF-120      # wires everything together
./scripts/worktree-agent.sh pf-enroll-portal PF-130    # needs pf-auth, pf-user-provisioning
./scripts/worktree-agent.sh pf-admin-ui PF-140         # needs all backend crates
./scripts/worktree-agent.sh pf-cache-node PF-150       # embeds multiple crates
```

---

## Step 7: Merge Flow

Each agent commits to its feature branch with conventional commits:

```
feat(auth): implement OIDC authorization code flow with PKCE
sec(auth): add DoD PKI trust store loading with chain validation

NIST-800-53: IA-5(2)
```

When an agent is done:

```bash
# From the worktree directory, the agent pushes:
git push origin feat/pf-auth/PF-010

# Open a PR (or merge directly for solo work):
# On GitHub: PR from feat/pf-auth/PF-010 → main
# Locally:
cd /path/to/printforge  # main worktree
git merge feat/pf-auth/PF-010
git push origin main

# Clean up:
git worktree remove .worktrees/pf-auth
git branch -d feat/pf-auth/PF-010
```

---

## Step 8: CI Verification

Every PR (or push to main) triggers the CI pipeline (`.github/workflows/ci.yaml`):

1. **Commit lint** — Conventional commits format enforced
2. **Format** — `cargo fmt --check`
3. **Clippy** — Pedantic lints, deny warnings
4. **Test** — `cargo nextest` with PostgreSQL service container
5. **Security** — `cargo audit` + `cargo deny` + SPDX header check + secrets scan
6. **SBOM** — CycloneDX SBOM generated on main branch pushes

All six jobs must pass before merging.

---

## Day-to-Day Commands

```bash
# Full workspace check (fast, do this often)
cargo check --workspace

# Run all tests
cargo nextest run --workspace

# Run one crate's tests
cargo nextest run -p pf-auth

# Run only NIST compliance evidence tests
cargo nextest run -E 'test(nist_)'

# Pre-commit security review (run before every commit)
./scripts/security-review.sh

# Generate NIST compliance evidence report
./scripts/nist-control-check.sh

# Check for license/advisory issues after adding a dependency
cargo deny check

# Format code
cargo fmt --all

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

---

## Project Build Order (Dependency Graph)

```
pf-common           ← Build first (no dependencies)
    │
    ├── pf-auth
    ├── pf-audit
    ├── pf-spool
    ├── pf-fleet-mgr
    ├── pf-policy-engine
    ├── pf-accounting
    │
    ├── pf-job-queue          ← depends on pf-spool, pf-auth, pf-policy-engine
    ├── pf-user-provisioning  ← depends on pf-auth
    ├── pf-firmware-mgr       ← depends on pf-fleet-mgr
    ├── pf-supply             ← depends on pf-fleet-mgr
    ├── pf-driver-service     ← depends on pf-job-queue
    │
    ├── pf-api-gateway        ← depends on pf-auth + all service crates
    ├── pf-enroll-portal      ← depends on pf-auth, pf-user-provisioning
    ├── pf-admin-ui           ← depends on all service crates
    └── pf-cache-node         ← embeds pf-job-queue, pf-auth, pf-spool, pf-fleet-mgr, pf-driver-service
```

---

## Troubleshooting

**`cargo check` fails with "can't find crate"**
→ Run `scripts/bootstrap.sh` to generate missing `Cargo.toml` files.

**Agent modified pf-common and broke other crates**
→ The agent should have opened a draft PR tagged `needs-review: pf-common`. Revert the pf-common changes, review, and re-apply.

**Worktree branch conflicts on merge**
→ Agents in different groups shouldn't conflict. If they do, it's likely a `pf-common` change. Resolve in `pf-common` first, then rebase the conflicting branch.

**`cargo deny check` fails on a new dependency**
→ Check if the dependency uses AGPL/GPL. If so, find an alternative with a permissive license. If it's a false positive (dual-licensed crate), add a `[[licenses.clarify]]` entry in `deny.toml`.

**`security-review.sh` flags a potential EDIPI**
→ Check if it's in test fixtures (allowed) or production code (not allowed). Test EDIPIs must be obviously synthetic: `1234567890`.

**Claude Code agent doesn't know about PrintForge**
→ Make sure it reads the CLAUDE.md files. Start the session with: "Read CLAUDE.md and crates/pf-<name>/CLAUDE.md, then begin implementation."
