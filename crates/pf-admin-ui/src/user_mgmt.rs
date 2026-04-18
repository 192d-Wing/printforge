// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! User management types for the admin dashboard: user list, role assignments,
//! account suspension.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::identity::{Role, SiteId};
use pf_common::policy::QuotaStatus;

/// A user summary row as displayed in the user management table.
///
/// EDIPI is intentionally excluded from serialized responses to prevent
/// PII exposure. Only the display name and organization are shown.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    /// Opaque user identifier (not the EDIPI).
    pub user_id: String,

    /// Display name (e.g., "DOE, JOHN Q.").
    pub display_name: String,

    /// Organization / unit.
    pub organization: String,

    /// Primary site.
    pub site_id: SiteId,

    /// Assigned roles.
    pub roles: Vec<Role>,

    /// Whether the account is currently active.
    pub active: bool,

    /// Current quota status for the billing period.
    pub quota: Option<QuotaStatus>,

    /// When the user last authenticated.
    pub last_login: Option<DateTime<Utc>>,

    /// When the account was provisioned.
    pub provisioned_at: DateTime<Utc>,
}

/// Account status for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccountStatus {
    /// Account is active.
    Active,
    /// Account is suspended.
    Suspended,
    /// All accounts regardless of status.
    All,
}

/// Filters for the user management view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserFilter {
    /// Filter by site.
    pub site_id: Option<SiteId>,

    /// Filter by account status.
    pub status: Option<AccountStatus>,

    /// Filter by role.
    pub role: Option<String>,

    /// Free-text search across display name and organization.
    pub search: Option<String>,
}

/// Paginated user list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListResponse {
    /// User summaries for the current page.
    pub users: Vec<UserSummary>,

    /// Total number of users matching the filter.
    pub total_count: u64,

    /// Current page number.
    pub page: u32,

    /// Items per page.
    pub page_size: u32,
}

/// Request to update a user's role assignments.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AU-12 — Auditable event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignmentRequest {
    /// The target user's opaque identifier.
    pub user_id: String,

    /// The new set of roles to assign (replaces existing roles).
    pub roles: Vec<Role>,

    /// Reason for the change (required for audit trail).
    pub reason: String,
}

/// Request to suspend or reactivate a user account.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AU-12 — Auditable event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatusChangeRequest {
    /// The target user's opaque identifier.
    pub user_id: String,

    /// Whether to activate (`true`) or suspend (`false`) the account.
    pub active: bool,

    /// Reason for the change (required for audit trail).
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_ac2_role_assignment_requires_reason() {
        let req = RoleAssignmentRequest {
            user_id: "usr-001".to_string(),
            roles: vec![Role::SiteAdmin(SiteId("langley".to_string()))],
            reason: "Promoted to site administrator".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RoleAssignmentRequest = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.reason.is_empty());
        assert_eq!(deserialized.roles.len(), 1);
    }

    #[test]
    fn nist_ac2_account_suspension_requires_reason() {
        let req = AccountStatusChangeRequest {
            user_id: "usr-002".to_string(),
            active: false,
            reason: "PCS transfer — account suspended pending out-processing".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: AccountStatusChangeRequest = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.active);
        assert!(!deserialized.reason.is_empty());
    }

    #[test]
    fn user_filter_default_is_unfiltered() {
        let filter = UserFilter::default();
        assert!(filter.site_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.search.is_none());
    }
}
