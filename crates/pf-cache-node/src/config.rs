// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration types for the `pf-cache-node` crate.
//!
//! Covers the central plane URL, `NATS` cluster, heartbeat interval,
//! `DDIL` thresholds, auth cache TTL, and local spool settings.

use std::path::PathBuf;
use std::time::Duration;

use pf_common::config::{NatsConfig, TlsConfig};
use pf_common::identity::SiteId;
use serde::{Deserialize, Serialize};

/// Top-level configuration for a cache node deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheNodeConfig {
    /// Unique identifier for this installation site.
    pub site_id: SiteId,
    /// Configuration for connecting to the central management plane.
    pub central: CentralConfig,
    /// `NATS` leaf node configuration.
    pub nats: NatsConfig,
    /// Heartbeat and `DDIL` threshold settings.
    pub heartbeat: HeartbeatConfig,
    /// Auth cache settings.
    pub auth_cache: AuthCacheConfig,
    /// Local `RustFS` spool configuration.
    pub local_spool: LocalSpoolConfig,
    /// Fleet proxy configuration.
    pub fleet_proxy: FleetProxyConfig,
    /// Prometheus metrics endpoint configuration.
    pub metrics: MetricsConfig,
}

/// Central management plane connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CentralConfig {
    /// Base URL of the central management plane API.
    pub url: String,
    /// TLS configuration for the central connection (mTLS required).
    pub tls: TlsConfig,
}

/// Heartbeat and `DDIL` mode transition thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Interval between heartbeat attempts to the central plane.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Number of consecutive heartbeat failures before entering `DDIL` mode.
    pub ddil_threshold: u32,
    /// Number of consecutive failures before entering `Degraded` mode.
    pub degraded_threshold: u32,
    /// Timeout for each individual heartbeat request.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            ddil_threshold: 3,
            degraded_threshold: 1,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Authentication cache settings.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — cached OCSP responses and
/// cert-to-EDIPI mappings with configurable TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCacheConfig {
    /// Time-to-live for cached OCSP responses and cert-to-EDIPI mappings.
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    /// Maximum number of entries in the auth cache.
    pub max_entries: usize,
}

impl Default for AuthCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(4 * 60 * 60), // 4 hours
            max_entries: 10_000,
        }
    }
}

/// Local `RustFS` spool store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSpoolConfig {
    /// Path to the local `RustFS` data directory.
    pub data_dir: PathBuf,
    /// Local `RustFS` listen address.
    pub listen_addr: String,
    /// Maximum spool capacity in bytes.
    pub max_capacity_bytes: u64,
    /// Whether data-at-rest encryption is enabled (must be true for production).
    pub encrypt_at_rest: bool,
}

impl Default for LocalSpoolConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/printforge/spool"),
            listen_addr: "127.0.0.1:9000".to_string(),
            max_capacity_bytes: 50 * 1024 * 1024 * 1024, // 50 GiB
            encrypt_at_rest: true,
        }
    }
}

/// Fleet proxy configuration for direct printer communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProxyConfig {
    /// `SNMPv3` community/credentials configuration path.
    pub snmp_credentials_path: PathBuf,
    /// Polling interval for local printer status.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
}

impl Default for FleetProxyConfig {
    fn default() -> Self {
        Self {
            snmp_credentials_path: PathBuf::from("/etc/printforge/snmp.conf"),
            poll_interval: Duration::from_secs(60),
        }
    }
}

/// Prometheus metrics endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Address to bind the metrics HTTP endpoint.
    pub listen_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9090".to_string(),
        }
    }
}

/// Serialize/deserialize `Duration` as human-readable strings (e.g. "30s", "4h").
mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}s", duration.as_secs());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_suffix('s') {
            rest.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| format!("invalid seconds: {e}"))
        } else if let Some(rest) = s.strip_suffix('m') {
            rest.parse::<u64>()
                .map(|m| Duration::from_secs(m * 60))
                .map_err(|e| format!("invalid minutes: {e}"))
        } else if let Some(rest) = s.strip_suffix('h') {
            rest.parse::<u64>()
                .map(|h| Duration::from_secs(h * 3600))
                .map_err(|e| format!("invalid hours: {e}"))
        } else {
            s.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| format!("invalid duration '{s}': {e}"))
        }
    }
}

/// Error type for configuration loading failures.
#[derive(Debug)]
pub struct ConfigError {
    /// The environment variable name that caused the error.
    pub var: String,
    /// Human-readable description of the parse failure.
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid value for {}: {}", self.var, self.message)
    }
}

impl std::error::Error for ConfigError {}

impl CacheNodeConfig {
    /// Applies environment variable overrides with the `PF_CN_` prefix to an
    /// existing [`CacheNodeConfig`] (typically loaded from a config file).
    ///
    /// This method does NOT construct a full config from scratch — the base
    /// config must be loaded from a file first since required fields like
    /// `site_id` and `central` have no sensible defaults.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_CN_HEARTBEAT_INTERVAL_SECS` | `u64` | Heartbeat interval in seconds |
    /// | `PF_CN_DDIL_THRESHOLD` | `u32` | Consecutive failures before DDIL mode |
    /// | `PF_CN_DEGRADED_THRESHOLD` | `u32` | Consecutive failures before Degraded mode |
    /// | `PF_CN_HEARTBEAT_TIMEOUT_SECS` | `u64` | Per-heartbeat request timeout |
    /// | `PF_CN_AUTH_CACHE_TTL_SECS` | `u64` | Auth cache entry TTL in seconds |
    /// | `PF_CN_AUTH_CACHE_MAX_ENTRIES` | `usize` | Max auth cache entries |
    /// | `PF_CN_SPOOL_DATA_DIR` | `String` | Local `RustFS` data directory path |
    /// | `PF_CN_SPOOL_LISTEN_ADDR` | `String` | Local `RustFS` listen address |
    /// | `PF_CN_SPOOL_MAX_CAPACITY_BYTES` | `u64` | Maximum spool capacity in bytes |
    /// | `PF_CN_METRICS_LISTEN_ADDR` | `String` | Prometheus metrics endpoint address |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        // Heartbeat overrides.
        if let Ok(val) = std::env::var("PF_CN_HEARTBEAT_INTERVAL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_HEARTBEAT_INTERVAL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            self.heartbeat.interval = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_CN_DDIL_THRESHOLD") {
            self.heartbeat.ddil_threshold = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_DDIL_THRESHOLD".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_CN_DEGRADED_THRESHOLD") {
            self.heartbeat.degraded_threshold = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_DEGRADED_THRESHOLD".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_CN_HEARTBEAT_TIMEOUT_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_HEARTBEAT_TIMEOUT_SECS".to_string(),
                message: format!("{e}"),
            })?;
            self.heartbeat.timeout = Duration::from_secs(secs);
        }

        // Auth cache overrides.
        if let Ok(val) = std::env::var("PF_CN_AUTH_CACHE_TTL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_AUTH_CACHE_TTL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            self.auth_cache.ttl = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_CN_AUTH_CACHE_MAX_ENTRIES") {
            self.auth_cache.max_entries = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_AUTH_CACHE_MAX_ENTRIES".to_string(),
                message: format!("{e}"),
            })?;
        }

        // Local spool overrides.
        if let Ok(val) = std::env::var("PF_CN_SPOOL_DATA_DIR") {
            self.local_spool.data_dir = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("PF_CN_SPOOL_LISTEN_ADDR") {
            self.local_spool.listen_addr = val;
        }

        if let Ok(val) = std::env::var("PF_CN_SPOOL_MAX_CAPACITY_BYTES") {
            self.local_spool.max_capacity_bytes = val.parse().map_err(|e| ConfigError {
                var: "PF_CN_SPOOL_MAX_CAPACITY_BYTES".to_string(),
                message: format!("{e}"),
            })?;
        }

        // Metrics overrides.
        if let Ok(val) = std::env::var("PF_CN_METRICS_LISTEN_ADDR") {
            self.metrics.listen_addr = val;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_config_default_values() {
        let cfg = HeartbeatConfig::default();
        assert_eq!(cfg.interval, Duration::from_secs(30));
        assert_eq!(cfg.ddil_threshold, 3);
        assert_eq!(cfg.degraded_threshold, 1);
    }

    #[test]
    fn auth_cache_default_ttl_is_four_hours() {
        let cfg = AuthCacheConfig::default();
        assert_eq!(cfg.ttl, Duration::from_secs(4 * 60 * 60));
    }

    #[test]
    fn local_spool_default_encryption_enabled() {
        let cfg = LocalSpoolConfig::default();
        assert!(cfg.encrypt_at_rest);
    }

    #[test]
    fn heartbeat_config_serialization_roundtrip() {
        let cfg = HeartbeatConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: HeartbeatConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.interval, cfg.interval);
        assert_eq!(deserialized.ddil_threshold, cfg.ddil_threshold);
    }

    /// Helper to build a minimal [`CacheNodeConfig`] for testing env overrides.
    fn test_cache_node_config() -> CacheNodeConfig {
        CacheNodeConfig {
            site_id: SiteId("TEST-SITE-001".to_string()),
            central: CentralConfig {
                url: "https://central.example.com".to_string(),
                tls: pf_common::config::TlsConfig {
                    cert_path: PathBuf::from("/etc/printforge/tls/client.crt"),
                    key_path: PathBuf::from("/etc/printforge/tls/client.key"),
                    ca_bundle_path: Some(PathBuf::from("/etc/printforge/tls/ca.pem")),
                    require_client_cert: true,
                },
            },
            nats: NatsConfig {
                urls: "nats://localhost:4222".to_string(),
                tls: None,
                credentials_path: Some(PathBuf::from("/etc/printforge/nats.creds")),
            },
            heartbeat: HeartbeatConfig::default(),
            auth_cache: AuthCacheConfig::default(),
            local_spool: LocalSpoolConfig::default(),
            fleet_proxy: FleetProxyConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }

    #[test]
    fn apply_env_overrides_no_vars_preserves_defaults() {
        // When none of the PF_CN_* vars are set, apply_env_overrides preserves defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let mut cfg = test_cache_node_config();
        cfg.apply_env_overrides().expect("apply_env_overrides should succeed");

        assert_eq!(cfg.heartbeat.interval, Duration::from_secs(30));
        assert_eq!(cfg.heartbeat.ddil_threshold, 3);
        assert_eq!(cfg.auth_cache.ttl, Duration::from_secs(4 * 60 * 60));
    }

    #[test]
    fn config_error_displays_var_and_message() {
        let err = ConfigError {
            var: "PF_CN_DDIL_THRESHOLD".to_string(),
            message: "invalid digit found in string".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("PF_CN_DDIL_THRESHOLD"));
        assert!(msg.contains("invalid digit"));
    }
}
