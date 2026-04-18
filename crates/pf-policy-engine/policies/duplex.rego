# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Duplex enforcement policy.
#
# Forces duplex (two-sided) printing for jobs with more than 2 pages
# unless the user explicitly requested simplex AND has justification,
# or the printer does not support duplex.
#
# NIST 800-53 Rev 5: CM-7 — Least Functionality

package printforge.duplex

default modify := false

# Should force duplex if:
# 1. Job has more than 2 pages
# 2. Job is currently one-sided
# 3. Printer supports duplex
modify if {
    input.page_count > 2
    input.sides == "OneSided"
    input.printer_capabilities.duplex_supported == true
}

# The modification to apply.
modification["forced duplex (two-sided long-edge)"] if {
    modify
}
