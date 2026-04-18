# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Color printing restriction policy.
#
# Denies color jobs if the user does not have a color printing privilege
# or if the color quota is exceeded.
#
# NIST 800-53 Rev 5: AC-3 — Access Enforcement, AC-6 — Least Privilege

package printforge.color

default allow := true

# Color remaining quota.
color_remaining := input.quota_status.color_limit - input.quota_status.color_used

# Total pages for this job.
total_pages := input.page_count * input.copies

# A job is a color job if color mode is "Color" or "AutoDetect".
is_color_job if {
    input.color == "Color"
}

is_color_job if {
    input.color == "AutoDetect"
}

# Deny color job when color quota is exceeded.
deny["color quota exceeded"] if {
    is_color_job
    total_pages > color_remaining
}

# Override: allow is false when deny fires.
allow := false if {
    is_color_job
    total_pages > color_remaining
}
