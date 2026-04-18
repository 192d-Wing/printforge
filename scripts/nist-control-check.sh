#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors
#
# nist-control-check.sh — Generate NIST 800-53 Rev 5 compliance evidence report
#
# Usage: ./scripts/nist-control-check.sh [control-family]
# Example: ./scripts/nist-control-check.sh IA    # Just Identification & Authentication
#          ./scripts/nist-control-check.sh        # All control families

set -euo pipefail

FAMILY="${1:-all}"
REPORT_DIR="docs/nist-evidence"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "${REPORT_DIR}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NIST 800-53 Rev 5 — Compliance Evidence Report             ║"
echo "║  Generated: ${TIMESTAMP}                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Run NIST evidence tests ──────────────────────────────────────────────────
if [[ "${FAMILY}" == "all" ]]; then
    FILTER="test(nist_)"
else
    FILTER="test(nist_${FAMILY,,})"
fi

echo "▸ Running NIST evidence tests (filter: ${FILTER})..."
echo ""

REPORT_FILE="${REPORT_DIR}/nist-evidence-${TIMESTAMP}.txt"

{
    echo "NIST 800-53 Rev 5 Compliance Evidence Report"
    echo "Generated: ${TIMESTAMP}"
    echo "Filter: ${FAMILY}"
    echo "============================================="
    echo ""
    echo "Test Results:"
    echo "-------------"
} > "${REPORT_FILE}"

if cargo nextest run --workspace -E "${FILTER}" --no-fail-fast 2>&1 | tee -a "${REPORT_FILE}"; then
    echo ""
    echo "✓ All NIST evidence tests passed"
else
    echo ""
    echo "✗ Some NIST evidence tests failed — review report at ${REPORT_FILE}"
fi

# ─── Count controls with evidence ─────────────────────────────────────────────
echo ""
echo "▸ Control coverage summary:"

for family in AC AU IA SC SI; do
    COUNT=$(grep -r "nist_${family,,}" crates/ --include="*.rs" -l 2>/dev/null | wc -l)
    TESTS=$(grep -r "fn nist_${family,,}" crates/ --include="*.rs" 2>/dev/null | wc -l)
    echo "  ${family}: ${COUNT} file(s) with evidence, ${TESTS} test(s)"
done

echo ""
echo "Report saved to: ${REPORT_FILE}"
