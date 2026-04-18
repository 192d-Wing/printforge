// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! User entity for `PrintForge` provisioning.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! The `ProvisionedUser` struct represents a user account within `PrintForge`.
//! Users are created via JIT provisioning or `SCIM` 2.0. User records are
//! never hard-deleted; deactivation sets `status` to `Suspended`.

use chrono::{DateTime, Utc};
use pf_common::identity::{Edipi, Role};
use pf_common::job::CostCenter;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The lifecycle status of a provisioned user account.
///
/// **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserStatus {
    /// Account is active and may authenticate.
    Active,
    /// Account is suspended (deprovisioned). Cannot authenticate.
    Suspended,
}

/// The source that created or last modified the user record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvisioningSource {
    /// Created via Just-In-Time provisioning on first login.
    Jit,
    /// Created or updated via `SCIM` 2.0 endpoint.
    Scim,
    /// Updated via attribute synchronization on subsequent login.
    AttributeSync,
}

/// User-configurable print preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPreferences {
    /// Preferred default color mode (`color` or `grayscale`).
    pub default_color_mode: String,
    /// Preferred default duplex setting.
    pub default_duplex: bool,
    /// Preferred default paper size (e.g., `letter`, `a4`).
    pub default_media_size: String,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            default_color_mode: "grayscale".to_string(),
            default_duplex: true,
            default_media_size: "letter".to_string(),
        }
    }
}

/// A provisioned user account in `PrintForge`.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
///
/// Contains the user's identity attributes (synced from the `IdP`), assigned
/// roles, cost centers, preferences, and lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionedUser {
    /// Internal unique identifier (`UUIDv4`).
    pub id: Uuid,

    /// The user's validated EDIPI (from `IdP` claims or `SCIM`).
    pub edipi: Edipi,

    /// Display name (e.g., `"Doe, John Q."`).
    pub display_name: String,

    /// Organizational unit / command (from `IdP` claims).
    pub organization: String,

    /// Site / installation the user is attributed to (from `IdP` claim
    /// `site` or `site_id`). Empty string means "unattributed" — such
    /// users are visible only under a Fleet Admin scope.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    #[serde(default)]
    pub site_id: String,

    /// Assigned `PrintForge` roles (derived from `IdP` group mappings).
    pub roles: Vec<Role>,

    /// Assigned cost centers for chargeback.
    pub cost_centers: Vec<CostCenter>,

    /// User-configurable print preferences.
    pub preferences: UserPreferences,

    /// Current account status.
    pub status: UserStatus,

    /// How the user was originally provisioned.
    pub provisioning_source: ProvisioningSource,

    /// When the user record was created.
    pub created_at: DateTime<Utc>,

    /// When the user record was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the user last authenticated (if ever).
    pub last_login_at: Option<DateTime<Utc>>,
}

impl ProvisionedUser {
    /// Returns `true` if the user account is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new("1234567890").unwrap(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "Test Unit, Test Base AFB".to_string(),
            site_id: String::new(),
            roles: vec![Role::User],
            cost_centers: vec![CostCenter::new("CC001", "Test Cost Center").unwrap()],
            preferences: UserPreferences::default(),
            status: UserStatus::Active,
            provisioning_source: ProvisioningSource::Jit,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        }
    }

    #[test]
    fn active_user_is_active() {
        let user = test_user();
        assert!(user.is_active());
    }

    #[test]
    fn suspended_user_is_not_active() {
        let mut user = test_user();
        user.status = UserStatus::Suspended;
        assert!(!user.is_active());
    }

    #[test]
    fn default_preferences() {
        let prefs = UserPreferences::default();
        assert_eq!(prefs.default_color_mode, "grayscale");
        assert!(prefs.default_duplex);
        assert_eq!(prefs.default_media_size, "letter");
    }

    #[test]
    fn user_serialization_roundtrip() {
        let user = test_user();
        let json = serde_json::to_string(&user).unwrap();
        let deserialized: ProvisionedUser = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.display_name, user.display_name);
        assert_eq!(deserialized.status, user.status);
    }
}
