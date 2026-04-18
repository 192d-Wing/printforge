#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors
#
# worktree-agent.sh — Launch a Claude Code agent in an isolated git worktree
#
# Usage: ./scripts/worktree-agent.sh <crate-name> [ticket-id]
# Example: ./scripts/worktree-agent.sh pf-auth PF-042
#
# This script:
#   1. Creates a git worktree at .worktrees/<crate-name>
#   2. Checks out a feature branch: feat/<crate-name>/<ticket-id>
#   3. Opens Claude Code in that worktree
#   4. On exit, optionally commits and pushes

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CRATE="${1:?Usage: worktree-agent.sh <crate-name> [ticket-id]}"
TICKET="${2:-$(date +%Y%m%d-%H%M%S)}"
WORKTREE_DIR="${REPO_ROOT}/.worktrees/${CRATE}"
BRANCH="feat/${CRATE}/${TICKET}"

# ─── Validate crate exists ────────────────────────────────────────────────────
if [[ ! -d "${REPO_ROOT}/crates/${CRATE}" ]]; then
    echo "ERROR: Crate '${CRATE}' not found in crates/ directory."
    echo "Available crates:"
    ls -1 "${REPO_ROOT}/crates/"
    exit 1
fi

# ─── Ensure main is up to date ────────────────────────────────────────────────
echo "▸ Fetching latest from origin..."
git fetch origin main --quiet

# ─── Create or reuse worktree ──────────────────────────────────────────────────
if [[ -d "${WORKTREE_DIR}" ]]; then
    echo "▸ Worktree already exists at ${WORKTREE_DIR}"
    echo "  Reusing existing worktree. Branch: $(git -C "${WORKTREE_DIR}" branch --show-current)"
else
    echo "▸ Creating worktree at ${WORKTREE_DIR} on branch ${BRANCH}"
    git worktree add -b "${BRANCH}" "${WORKTREE_DIR}" origin/main
fi

# ─── Copy workspace-level configs into worktree ──────────────────────────────
# (Worktrees share .git but need these for cargo commands)
for f in deny.toml clippy.toml rustfmt.toml; do
    if [[ -f "${REPO_ROOT}/${f}" ]]; then
        cp "${REPO_ROOT}/${f}" "${WORKTREE_DIR}/${f}" 2>/dev/null || true
    fi
done

# ─── Agent boundary manifest ──────────────────────────────────────────────────
cat > "${WORKTREE_DIR}/.agent-scope.json" << EOF
{
  "agent_id": "${CRATE}-${TICKET}",
  "crate": "${CRATE}",
  "ticket": "${TICKET}",
  "branch": "${BRANCH}",
  "allowed_paths": [
    "crates/${CRATE}/",
    "crates/pf-common/src/"
  ],
  "read_only_paths": [
    "CLAUDE.md",
    "Cargo.toml",
    "deny.toml",
    "crates/pf-common/Cargo.toml"
  ],
  "forbidden_paths": [
    "crates/pf-*/  (except ${CRATE} and pf-common)",
    ".github/",
    "deploy/",
    "scripts/"
  ],
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  PrintForge Agent: ${CRATE}                                "
echo "║  Ticket: ${TICKET}                                         "
echo "║  Branch: ${BRANCH}                                         "
echo "║  Worktree: ${WORKTREE_DIR}                                 "
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  ALLOWED: crates/${CRATE}/, crates/pf-common/src/          "
echo "║  READ ONLY: CLAUDE.md, Cargo.toml, deny.toml               "
echo "║  FORBIDDEN: other crates, .github, deploy, scripts         "
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Commit format: <type>(${CRATE#pf-}): <description>       "
echo "║  Security commits: sec(${CRATE#pf-}): <desc>              "
echo "║    Footer: NIST-800-53: <control-id>                       "
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Launch Claude Code ────────────────────────────────────────────────────────
echo "▸ Launching Claude Code in worktree..."
cd "${WORKTREE_DIR}"

# If claude CLI is available, launch it; otherwise just open a shell
if command -v claude &> /dev/null; then
    claude --print "Read CLAUDE.md and crates/${CRATE}/CLAUDE.md, then begin implementation for ticket ${TICKET}."
else
    echo "  Claude Code CLI not found. Dropping into shell."
    echo "  Run: claude --print \"Read CLAUDE.md and crates/${CRATE}/CLAUDE.md\""
    exec "${SHELL:-bash}"
fi
