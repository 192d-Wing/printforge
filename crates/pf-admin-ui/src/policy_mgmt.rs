// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Policy management types for the admin dashboard: view Rego policies,
//! edit quota overrides, toggle settings.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, CM-3 — Configuration
//! Change Control

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::identity::SiteId;

/// A policy rule as viewed in the admin dashboard.
///
/// **NIST 800-53 Rev 5:** CM-3 — Configuration Change Control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    /// Unique policy identifier.
    pub policy_id: Uuid,

    /// Human-readable policy name.
    pub name: String,

    /// Description of what the policy enforces.
    pub description: String,

    /// Whether the policy is currently active.
    pub enabled: bool,

    /// Sites this policy applies to. Empty means all sites (global).
    pub applicable_sites: Vec<SiteId>,

    /// When the policy was last modified.
    pub last_modified: DateTime<Utc>,

    /// Display name of the admin who last modified.
    pub modified_by: String,
}

/// A quota override for a specific user or cost center.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaOverride {
    /// Unique override identifier.
    pub override_id: Uuid,

    /// The target of the override (user display name or cost center code).
    pub target: String,

    /// The type of target.
    pub target_type: QuotaTargetType,

    /// Site the override applies to.
    pub site_id: SiteId,

    /// Overridden page limit (per period).
    pub page_limit: u32,

    /// Overridden color page limit (per period).
    pub color_page_limit: u32,

    /// When the override expires (if temporary).
    pub expires_at: Option<DateTime<Utc>>,

    /// Reason for the override.
    pub reason: String,

    /// Display name of the admin who created the override.
    pub created_by: String,

    /// When the override was created.
    pub created_at: DateTime<Utc>,
}

/// Type of entity that a quota override targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuotaTargetType {
    /// Override applies to a specific user.
    User,
    /// Override applies to an entire cost center.
    CostCenter,
}

/// Request to create or update a quota override.
///
/// **NIST 800-53 Rev 5:** CM-3 — Changes are audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaOverrideRequest {
    /// The target identifier (EDIPI or cost center code).
    pub target: String,

    /// The type of target.
    pub target_type: QuotaTargetType,

    /// Site the override applies to.
    pub site_id: SiteId,

    /// New page limit.
    pub page_limit: u32,

    /// New color page limit.
    pub color_page_limit: u32,

    /// When the override should expire (if temporary).
    pub expires_at: Option<DateTime<Utc>>,

    /// Reason for the override (required for audit trail).
    pub reason: String,
}

/// Request to toggle a policy's enabled state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyToggleRequest {
    /// The policy to toggle.
    pub policy_id: Uuid,

    /// New enabled state.
    pub enabled: bool,

    /// Reason for the change (required for audit trail).
    pub reason: String,
}

/// Paginated policy list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyListResponse {
    /// Policies for the current page.
    pub policies: Vec<PolicySummary>,

    /// Total number of policies.
    pub total_count: u64,

    /// Current page number.
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_override_request_serialization() {
        let req = QuotaOverrideRequest {
            target: "CC-001".to_string(),
            target_type: QuotaTargetType::CostCenter,
            site_id: SiteId("langley".to_string()),
            page_limit: 5000,
            color_page_limit: 500,
            expires_at: None,
            reason: "Temporary increase for end-of-quarter reporting".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: QuotaOverrideRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.page_limit, 5000);
        assert_eq!(deserialized.target_type, QuotaTargetType::CostCenter);
    }

    #[test]
    fn policy_toggle_request_requires_reason() {
        let req = PolicyToggleRequest {
            policy_id: Uuid::nil(),
            enabled: false,
            reason: "Disabling for maintenance window".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: PolicyToggleRequest = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.enabled);
        assert!(!deserialized.reason.is_empty());
    }
}
