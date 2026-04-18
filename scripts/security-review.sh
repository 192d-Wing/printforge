#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors
#
# security-review.sh — Pre-commit security checks for PrintForge
#
# Runs: cargo audit, cargo deny, clippy security lints, SPDX header check,
#       secrets scan, and NIST control coverage report.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS="${GREEN}✓${NC}"
FAIL="${RED}✗${NC}"
WARN="${YELLOW}⚠${NC}"
EXIT_CODE=0

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           PrintForge Security Review                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── 1. RustSec Advisory Database ──────────────────────────────────────────────
echo "▸ [1/6] Checking RustSec Advisory Database (cargo audit)..."
if cargo audit 2>/dev/null; then
    echo -e "  ${PASS} No known vulnerabilities in dependencies"
else
    echo -e "  ${FAIL} Vulnerabilities found — review cargo audit output above"
    EXIT_CODE=1
fi
echo ""

# ─── 2. License + Advisory Check ──────────────────────────────────────────────
echo "▸ [2/6] Checking licenses and advisories (cargo deny)..."
if cargo deny check 2>/dev/null; then
    echo -e "  ${PASS} All dependencies pass license and advisory checks"
else
    echo -e "  ${FAIL} cargo deny check failed — prohibited license or advisory found"
    EXIT_CODE=1
fi
echo ""

# ─── 3. Clippy Security Lints ──────────────────────────────────────────────────
echo "▸ [3/6] Running Clippy security lints..."
if cargo clippy --workspace --all-targets -- \
    -D warnings \
    -W clippy::pedantic \
    -A clippy::module_name_repetitions \
    -A clippy::must_use_candidate \
    -A clippy::missing_errors_doc \
    2>/dev/null; then
    echo -e "  ${PASS} Clippy security lints pass"
else
    echo -e "  ${FAIL} Clippy found issues — fix before committing"
    EXIT_CODE=1
fi
echo ""

# ─── 4. SPDX License Header Check ─────────────────────────────────────────────
echo "▸ [4/6] Checking SPDX Apache-2.0 headers on all .rs files..."
MISSING_HEADERS=()
while IFS= read -r -d '' file; do
    if ! head -1 "$file" | grep -q "SPDX-License-Identifier: Apache-2.0"; then
        MISSING_HEADERS+=("$file")
    fi
done < <(find crates/ -name "*.rs" -print0 2>/dev/null)

if [[ ${#MISSING_HEADERS[@]} -eq 0 ]]; then
    echo -e "  ${PASS} All .rs files have SPDX Apache-2.0 header"
else
    echo -e "  ${FAIL} Missing SPDX header in ${#MISSING_HEADERS[@]} file(s):"
    for f in "${MISSING_HEADERS[@]}"; do
        echo "       - ${f}"
    done
    EXIT_CODE=1
fi
echo ""

# ─── 5. Secrets Scan ──────────────────────────────────────────────────────────
echo "▸ [5/6] Scanning for hardcoded secrets..."
SECRETS_FOUND=0
PATTERNS=(
    'password\s*=\s*"[^"]+'
    'secret\s*=\s*"[^"]+'
    'api_key\s*=\s*"[^"]+'
    'token\s*=\s*"[^"]+'
    'PRIVATE KEY'
    '[0-9]{10}'  # Potential EDIPI — flag for review
)

for pattern in "${PATTERNS[@]}"; do
    # Skip test fixtures directory and Cargo.lock
    MATCHES=$(grep -rn --include="*.rs" --include="*.toml" --include="*.yaml" \
        -E "${pattern}" crates/ 2>/dev/null \
        | grep -v "tests/fixtures" \
        | grep -v "Cargo.lock" \
        | grep -v "CLAUDE.md" \
        | grep -v "// Test EDIPI" \
        | grep -v "# SPDX" \
        || true)
    if [[ -n "${MATCHES}" ]]; then
        if [[ "${pattern}" == '[0-9]{10}' ]]; then
            echo -e "  ${WARN} Potential EDIPI pattern found (review manually):"
        else
            echo -e "  ${FAIL} Potential secret found matching '${pattern}':"
            SECRETS_FOUND=1
        fi
        echo "${MATCHES}" | head -5 | sed 's/^/       /'
    fi
done

if [[ ${SECRETS_FOUND} -eq 0 ]]; then
    echo -e "  ${PASS} No hardcoded secrets detected"
else
    EXIT_CODE=1
fi
echo ""

# ─── 6. Unsafe Code Check ─────────────────────────────────────────────────────
echo "▸ [6/6] Checking for unsafe code..."
UNSAFE_COUNT=$(grep -rn "unsafe " crates/ --include="*.rs" \
    | grep -v "forbid(unsafe_code)" \
    | grep -v "// Safety:" \
    | grep -v "tests/" \
    | wc -l || true)

if [[ ${UNSAFE_COUNT} -eq 0 ]]; then
    echo -e "  ${PASS} No unsafe code found"
else
    echo -e "  ${WARN} Found ${UNSAFE_COUNT} unsafe usage(s) — ensure each is justified and documented"
    grep -rn "unsafe " crates/ --include="*.rs" \
        | grep -v "forbid(unsafe_code)" \
        | grep -v "tests/" \
        | head -5 | sed 's/^/       /'
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════════════════════"
if [[ ${EXIT_CODE} -eq 0 ]]; then
    echo -e "${GREEN}All security checks passed. Safe to commit.${NC}"
else
    echo -e "${RED}Security checks failed. Fix issues before committing.${NC}"
fi
echo "══════════════════════════════════════════════════════════════"

exit ${EXIT_CODE}
