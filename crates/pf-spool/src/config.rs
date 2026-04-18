// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration types for the `pf-spool` crate.
//!
//! Defines the `RustFS` endpoint, bucket, region, and key store settings.

use std::time::Duration;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Configuration for the `RustFS` S3-compatible object store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoolConfig {
    /// `RustFS` / S3 endpoint URL (e.g., `https://rustfs.local:9000`).
    pub endpoint: String,

    /// S3 bucket name for spool data.
    pub bucket: String,

    /// S3 region (use `us-east-1` for `RustFS` unless configured otherwise).
    pub region: String,

    /// Access key ID for S3 authentication.
    #[serde(skip)]
    pub access_key_id: Option<SecretString>,

    /// Secret access key for S3 authentication.
    #[serde(skip)]
    pub secret_access_key: Option<SecretString>,

    /// Whether to use path-style addressing (required for `RustFS`).
    pub force_path_style: bool,

    /// Key store configuration.
    pub key_store: KeyStoreConfig,

    /// Retention policy configuration.
    pub retention: RetentionConfig,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://localhost:9000".to_string(),
            bucket: "printforge-spool".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            force_path_style: true,
            key_store: KeyStoreConfig::default(),
            retention: RetentionConfig::default(),
        }
    }
}

/// Configuration for the KEK key store backend.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyStoreConfig {
    /// In-memory key store for development/testing only.
    #[default]
    InMemory,

    /// `HashiCorp` Vault transit backend.
    Vault {
        /// Vault server URL.
        url: String,
        /// Transit engine mount path.
        mount_path: String,
        /// Key name in the transit engine.
        key_name: String,
    },
}

/// Retention policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Default retention duration for spool data after job completion.
    #[serde(with = "humantime_serde")]
    pub default_retention: Duration,

    /// How often the purge task runs.
    #[serde(with = "humantime_serde")]
    pub purge_interval: Duration,

    /// Maximum retention duration (hard cap).
    #[serde(with = "humantime_serde")]
    pub max_retention: Duration,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            default_retention: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            purge_interval: Duration::from_secs(5 * 60),              // 5 minutes
            max_retention: Duration::from_secs(30 * 24 * 60 * 60),    // 30 days
        }
    }
}

/// Serialization helpers for `Duration` using human-readable strings.
mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let config = SpoolConfig::default();
        assert_eq!(config.bucket, "printforge-spool");
        assert!(config.force_path_style);
    }

    #[test]
    fn default_retention_is_seven_days() {
        let config = RetentionConfig::default();
        assert_eq!(
            config.default_retention,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
    }

    #[test]
    fn default_purge_interval_is_five_minutes() {
        let config = RetentionConfig::default();
        assert_eq!(config.purge_interval, Duration::from_secs(5 * 60));
    }
}
