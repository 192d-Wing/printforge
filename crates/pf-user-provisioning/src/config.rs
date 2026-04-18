// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration types for `pf-user-provisioning`.
//!
//! Defines the `SCIM` endpoint configuration, role mapping table,
//! default role assignment, and synchronization intervals.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::role_mapping::RoleMappingRule;

/// Top-level provisioning configuration.
///
/// Loaded from environment variables or configuration files at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningConfig {
    /// `SCIM` endpoint configuration (optional; JIT works without `SCIM`).
    pub scim: Option<ScimConfig>,

    /// Role mapping rules: `IdP` group pattern to `PrintForge` role.
    pub role_mappings: Vec<RoleMappingRule>,

    /// The default `PrintForge` role assigned when no mapping matches.
    ///
    /// Defaults to `User` if not configured.
    pub default_role: String,

    /// How often to run the attribute synchronization sweep (if enabled).
    ///
    /// Defaults to 1 hour.
    #[serde(with = "humantime_serde", default = "default_sync_interval")]
    pub sync_interval: Duration,

    /// Maximum number of `IdP` groups to evaluate per user.
    ///
    /// Prevents denial-of-service via excessively large group claims.
    #[serde(default = "default_max_groups")]
    pub max_groups_per_user: usize,

    /// Static `IdP` claim field name to cost center code mapping.
    ///
    /// For example: `{"department": "cost_center_code"}`.
    #[serde(default)]
    pub cost_center_claim_field: String,
}

impl Default for ProvisioningConfig {
    fn default() -> Self {
        Self {
            scim: None,
            role_mappings: Vec::new(),
            default_role: "User".to_string(),
            sync_interval: default_sync_interval(),
            max_groups_per_user: default_max_groups(),
            cost_center_claim_field: "cost_center".to_string(),
        }
    }
}

/// `SCIM` 2.0 endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimConfig {
    /// Base URL of the `SCIM` endpoint (e.g., `https://printforge.local/scim/v2`).
    pub base_url: Url,

    /// Whether the `SCIM` endpoint is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum number of resources per `SCIM` list response page.
    #[serde(default = "default_page_size")]
    pub page_size: usize,

    /// Maximum number of operations in a single `SCIM` bulk request.
    #[serde(default = "default_bulk_max_operations")]
    pub bulk_max_operations: usize,
}

fn default_sync_interval() -> Duration {
    Duration::from_secs(3600)
}

const fn default_max_groups() -> usize {
    100
}

const fn default_true() -> bool {
    true
}

const fn default_page_size() -> usize {
    100
}

const fn default_bulk_max_operations() -> usize {
    1000
}

/// Deserialization support for human-readable durations (e.g., `"1h"`, `"30m"`).
mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_user_role() {
        let config = ProvisioningConfig::default();
        assert_eq!(config.default_role, "User");
    }

    #[test]
    fn default_config_sync_interval_is_one_hour() {
        let config = ProvisioningConfig::default();
        assert_eq!(config.sync_interval, Duration::from_secs(3600));
    }

    #[test]
    fn default_config_max_groups_is_100() {
        let config = ProvisioningConfig::default();
        assert_eq!(config.max_groups_per_user, 100);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = ProvisioningConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProvisioningConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.default_role, config.default_role);
    }
}
