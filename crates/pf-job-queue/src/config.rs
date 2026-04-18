// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for the `pf-job-queue` crate.
//!
//! All durations and sizes are expressed in standard units with sensible
//! defaults suitable for a DAF installation.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for the job queue subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobQueueConfig {
    /// How long completed/failed jobs are retained before automatic purge.
    /// Default: 72 hours.
    #[serde(with = "humantime_serde", default = "default_retention_ttl")]
    pub retention_ttl: Duration,

    /// Maximum spool payload size per job in bytes.
    /// Default: 100 MiB.
    #[serde(default = "default_max_spool_bytes")]
    pub max_spool_bytes: u64,

    /// Interval between NATS sync heartbeats (local ↔ central).
    /// Default: 30 seconds.
    #[serde(with = "humantime_serde", default = "default_sync_interval")]
    pub sync_interval: Duration,

    /// Maximum number of concurrent job deliveries to printers.
    /// Default: 16.
    #[serde(default = "default_max_concurrent_deliveries")]
    pub max_concurrent_deliveries: usize,

    /// Interval between retention sweeps for expired jobs.
    /// Default: 10 minutes.
    #[serde(with = "humantime_serde", default = "default_purge_sweep_interval")]
    pub purge_sweep_interval: Duration,

    /// Maximum number of jobs purged in a single sweep to limit DB load.
    /// Default: 500.
    #[serde(default = "default_purge_batch_size")]
    pub purge_batch_size: u32,
}

impl Default for JobQueueConfig {
    fn default() -> Self {
        Self {
            retention_ttl: default_retention_ttl(),
            max_spool_bytes: default_max_spool_bytes(),
            sync_interval: default_sync_interval(),
            max_concurrent_deliveries: default_max_concurrent_deliveries(),
            purge_sweep_interval: default_purge_sweep_interval(),
            purge_batch_size: default_purge_batch_size(),
        }
    }
}

fn default_retention_ttl() -> Duration {
    Duration::from_secs(72 * 60 * 60)
}

const fn default_max_spool_bytes() -> u64 {
    100 * 1024 * 1024 // 100 MiB
}

fn default_sync_interval() -> Duration {
    Duration::from_secs(30)
}

const fn default_max_concurrent_deliveries() -> usize {
    16
}

fn default_purge_sweep_interval() -> Duration {
    Duration::from_secs(10 * 60)
}

const fn default_purge_batch_size() -> u32 {
    500
}

/// Serialization helpers for `Duration` using human-readable strings.
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

impl JobQueueConfig {
    /// Constructs a [`JobQueueConfig`] by reading environment variables with
    /// the `PF_JQ_` prefix. Falls back to [`Default`] values for any variable
    /// that is not set.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_JQ_RETENTION_DAYS` | `u64` | Retention period in days (converted to `Duration`) |
    /// | `PF_JQ_MAX_SPOOL_SIZE_BYTES` | `u64` | Maximum spool payload size per job |
    /// | `PF_JQ_SYNC_INTERVAL_SECS` | `u64` | NATS sync heartbeat interval in seconds |
    /// | `PF_JQ_MAX_CONCURRENT_DELIVERIES` | `usize` | Max concurrent job deliveries |
    /// | `PF_JQ_PURGE_SWEEP_INTERVAL_SECS` | `u64` | Purge sweep interval in seconds |
    /// | `PF_JQ_PURGE_BATCH_SIZE` | `u32` | Max jobs purged per sweep |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        if let Ok(val) = std::env::var("PF_JQ_RETENTION_DAYS") {
            let days: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_JQ_RETENTION_DAYS".to_string(),
                message: format!("{e}"),
            })?;
            cfg.retention_ttl = Duration::from_secs(days * 24 * 60 * 60);
        }

        if let Ok(val) = std::env::var("PF_JQ_MAX_SPOOL_SIZE_BYTES") {
            cfg.max_spool_bytes = val.parse().map_err(|e| ConfigError {
                var: "PF_JQ_MAX_SPOOL_SIZE_BYTES".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_JQ_SYNC_INTERVAL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_JQ_SYNC_INTERVAL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            cfg.sync_interval = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_JQ_MAX_CONCURRENT_DELIVERIES") {
            cfg.max_concurrent_deliveries = val.parse().map_err(|e| ConfigError {
                var: "PF_JQ_MAX_CONCURRENT_DELIVERIES".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_JQ_PURGE_SWEEP_INTERVAL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_JQ_PURGE_SWEEP_INTERVAL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            cfg.purge_sweep_interval = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_JQ_PURGE_BATCH_SIZE") {
            cfg.purge_batch_size = val.parse().map_err(|e| ConfigError {
                var: "PF_JQ_PURGE_BATCH_SIZE".to_string(),
                message: format!("{e}"),
            })?;
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = JobQueueConfig::default();
        assert_eq!(cfg.retention_ttl, Duration::from_secs(72 * 60 * 60));
        assert_eq!(cfg.max_spool_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.sync_interval, Duration::from_secs(30));
        assert_eq!(cfg.max_concurrent_deliveries, 16);
        assert_eq!(cfg.purge_sweep_interval, Duration::from_secs(600));
        assert_eq!(cfg.purge_batch_size, 500);
    }

    #[test]
    fn config_roundtrips_through_json() {
        let cfg = JobQueueConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: JobQueueConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.retention_ttl, cfg.retention_ttl);
        assert_eq!(parsed.max_spool_bytes, cfg.max_spool_bytes);
    }

    #[test]
    fn from_env_returns_defaults_when_no_vars_set() {
        // When none of the PF_JQ_* vars are set, from_env falls back to defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let cfg = JobQueueConfig::from_env().expect("from_env should succeed with defaults");
        let default_cfg = JobQueueConfig::default();
        assert_eq!(cfg.retention_ttl, default_cfg.retention_ttl);
        assert_eq!(cfg.max_spool_bytes, default_cfg.max_spool_bytes);
        assert_eq!(cfg.sync_interval, default_cfg.sync_interval);
        assert_eq!(cfg.max_concurrent_deliveries, default_cfg.max_concurrent_deliveries);
        assert_eq!(cfg.purge_sweep_interval, default_cfg.purge_sweep_interval);
        assert_eq!(cfg.purge_batch_size, default_cfg.purge_batch_size);
    }

    #[test]
    fn config_error_displays_var_and_message() {
        let err = ConfigError {
            var: "PF_JQ_RETENTION_DAYS".to_string(),
            message: "invalid digit found in string".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("PF_JQ_RETENTION_DAYS"));
        assert!(msg.contains("invalid digit"));
    }
}
