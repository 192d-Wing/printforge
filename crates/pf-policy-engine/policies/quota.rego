# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Quota enforcement policy.
#
# Denies jobs that exceed the user's monthly page quota.
# Issues a warning when usage exceeds 90% of the limit.
#
# NIST 800-53 Rev 5: AC-3 — Access Enforcement

package printforge.quota

default allow := false

# Total pages requested (page_count * copies).
total_pages := input.page_count * input.copies

# Remaining quota.
remaining := input.quota_status.limit - input.quota_status.used

# Allow if total pages fit within remaining quota.
allow if {
    total_pages <= remaining
}

# Deny reason when quota is exceeded.
deny["quota exceeded: monthly page limit reached"] if {
    total_pages > remaining
}

# Warning when usage exceeds 90% of limit.
warn["approaching quota limit (>90% used)"] if {
    input.quota_status.used > input.quota_status.limit * 0.9
    total_pages <= remaining
}
