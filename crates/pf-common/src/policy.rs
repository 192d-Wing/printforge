// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Policy evaluation types: `PolicyDecision`, `QuotaStatus`, `PolicyViolation`.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement

use serde::{Deserialize, Serialize};

/// The result of evaluating a print job against organizational policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Job is allowed as-is.
    Allow,
    /// Job is denied for the given reason.
    Deny(PolicyViolation),
    /// Job is allowed but with modifications applied (e.g., forced duplex).
    AllowWithModification { reason: String },
}

/// Describes why a policy evaluation denied a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyViolation {
    /// User has exceeded their page quota for the current period.
    QuotaExceeded,
    /// Color printing is not permitted by policy.
    ColorNotAllowed,
    /// Job exceeds the maximum page limit.
    PageLimitExceeded { limit: u32, requested: u32 },
    /// User does not have permission to print to the requested printer.
    PrinterNotAuthorized,
    /// A custom policy rule denied the job.
    Custom { rule: String, message: String },
}

/// Current quota consumption for a user in the billing period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaStatus {
    /// Total pages allowed this period.
    pub limit: u32,
    /// Pages consumed so far.
    pub used: u32,
    /// Color pages allowed this period.
    pub color_limit: u32,
    /// Color pages consumed so far.
    pub color_used: u32,
}

impl QuotaStatus {
    /// Pages remaining before quota is exhausted.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.limit.saturating_sub(self.used)
    }

    /// Color pages remaining before color quota is exhausted.
    #[must_use]
    pub fn color_remaining(&self) -> u32 {
        self.color_limit.saturating_sub(self.color_used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_remaining_saturates_at_zero() {
        let status = QuotaStatus {
            limit: 100,
            used: 150,
            color_limit: 50,
            color_used: 50,
        };
        assert_eq!(status.remaining(), 0);
        assert_eq!(status.color_remaining(), 0);
    }
}
