# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Per-job page limit policy.
#
# Denies jobs that exceed the maximum pages-per-job limit (default 500).
#
# NIST 800-53 Rev 5: AC-3 — Access Enforcement

package printforge.page_limit

import rego.v1

default allow := true

default max_pages := 500

# Total pages including copies.
total_pages := input.page_count * input.copies

# Deny when total pages exceed the limit.
deny contains msg if {
    total_pages > max_pages
    msg := sprintf("job exceeds maximum page limit: %d > %d", [total_pages, max_pages])
}

# Override allow when deny fires.
allow := false if {
    total_pages > max_pages
}
