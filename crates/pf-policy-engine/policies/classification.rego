# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Classification banner enforcement policy.
#
# Ensures that documents marked as CUI (Controlled Unclassified Information)
# have classification banners inserted on every page.
#
# NIST 800-53 Rev 5: AC-3 — Access Enforcement

package printforge.classification

import rego.v1

default modify := false

# If the document is marked CUI, require banner insertion.
modify if {
    input.classification == "CUI"
}

modification contains "insert CUI banner on all pages" if {
    modify
}

# CUI documents must not be printed on printers in uncontrolled areas.
deny contains "CUI documents cannot be printed on uncontrolled printers" if {
    input.classification == "CUI"
    input.printer_location_controlled == false
}
