// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Local `RustFS` spool instance management.
//!
//! Manages the local `RustFS` process that stores spool data for jobs
//! submitted at this installation. During `DDIL` mode, only locally-submitted
//! jobs are available for release.
//!
//! **NIST 800-53 Rev 5:** SC-28 — Protection of Information at Rest
//! Local spool data MUST be encrypted at rest using the DEK/KEK scheme.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::LocalSpoolConfig;
use crate::error::CacheNodeError;

/// Health status of the local `RustFS` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpoolHealth {
    /// The spool is healthy and accepting data.
    Healthy,
    /// The spool is running but experiencing issues (e.g., high latency).
    Degraded,
    /// The spool process is not running.
    Down,
    /// The spool is running but disk is nearly full.
    DiskPressure,
}

/// Statistics about the local spool instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoolStats {
    /// Current health status.
    pub health: SpoolHealth,
    /// Total capacity in bytes.
    pub capacity_bytes: u64,
    /// Used space in bytes.
    pub used_bytes: u64,
    /// Number of spool objects currently stored.
    pub object_count: u64,
    /// Timestamp of the last health check.
    pub last_check: DateTime<Utc>,
}

impl SpoolStats {
    /// Calculate the used capacity as a fraction (0.0 to 1.0).
    #[must_use]
    pub fn usage_fraction(&self) -> f64 {
        if self.capacity_bytes == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.used_bytes as f64 / self.capacity_bytes as f64
        }
    }
}

/// Manages the local `RustFS` spool instance lifecycle.
///
/// **NIST 800-53 Rev 5:** SC-28 — data is encrypted at rest.
#[derive(Debug)]
pub struct LocalSpoolManager {
    /// Configuration for the local spool.
    config: LocalSpoolConfig,
    /// Current health status.
    health: SpoolHealth,
    /// Latest statistics snapshot.
    latest_stats: Option<SpoolStats>,
}

impl LocalSpoolManager {
    /// Create a new `LocalSpoolManager` with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Config` if encryption at rest is disabled
    /// (required for NIST SC-28 compliance).
    pub fn new(config: LocalSpoolConfig) -> Result<Self, CacheNodeError> {
        if !config.encrypt_at_rest {
            return Err(CacheNodeError::Config {
                message: "encrypt_at_rest must be enabled for NIST SC-28 compliance".to_string(),
            });
        }
        Ok(Self {
            config,
            health: SpoolHealth::Down,
            latest_stats: None,
        })
    }

    /// Return the data directory path.
    #[must_use]
    pub fn data_dir(&self) -> &PathBuf {
        &self.config.data_dir
    }

    /// Return the listen address.
    #[must_use]
    pub fn listen_addr(&self) -> &str {
        &self.config.listen_addr
    }

    /// Return the current health status.
    #[must_use]
    pub fn health(&self) -> SpoolHealth {
        self.health
    }

    /// Return the latest statistics, if available.
    #[must_use]
    pub fn latest_stats(&self) -> Option<&SpoolStats> {
        self.latest_stats.as_ref()
    }

    /// Update the health status and statistics from a health check.
    pub fn update_health(&mut self, stats: SpoolStats) {
        self.health = stats.health;
        tracing::debug!(
            health = ?stats.health,
            usage_pct = format!("{:.1}%", stats.usage_fraction() * 100.0),
            "local spool health check"
        );
        self.latest_stats = Some(stats);
    }

    /// Mark the spool as started.
    pub fn mark_started(&mut self) {
        self.health = SpoolHealth::Healthy;
        tracing::info!(
            data_dir = %self.config.data_dir.display(),
            listen_addr = %self.config.listen_addr,
            "local RustFS spool started"
        );
    }

    /// Mark the spool as stopped.
    pub fn mark_stopped(&mut self) {
        self.health = SpoolHealth::Down;
        tracing::info!("local RustFS spool stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> LocalSpoolConfig {
        LocalSpoolConfig::default()
    }

    #[test]
    fn nist_sc28_rejects_unencrypted_config() {
        let mut config = default_config();
        config.encrypt_at_rest = false;
        let result = LocalSpoolManager::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn nist_sc28_accepts_encrypted_config() {
        let config = default_config();
        assert!(config.encrypt_at_rest);
        let manager = LocalSpoolManager::new(config).unwrap();
        assert_eq!(manager.health(), SpoolHealth::Down);
    }

    #[test]
    fn mark_started_sets_healthy() {
        let mut manager = LocalSpoolManager::new(default_config()).unwrap();
        manager.mark_started();
        assert_eq!(manager.health(), SpoolHealth::Healthy);
    }

    #[test]
    fn mark_stopped_sets_down() {
        let mut manager = LocalSpoolManager::new(default_config()).unwrap();
        manager.mark_started();
        manager.mark_stopped();
        assert_eq!(manager.health(), SpoolHealth::Down);
    }

    #[test]
    fn spool_stats_usage_fraction() {
        let stats = SpoolStats {
            health: SpoolHealth::Healthy,
            capacity_bytes: 1000,
            used_bytes: 250,
            object_count: 10,
            last_check: Utc::now(),
        };
        assert!((stats.usage_fraction() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn spool_stats_zero_capacity_returns_zero() {
        let stats = SpoolStats {
            health: SpoolHealth::Healthy,
            capacity_bytes: 0,
            used_bytes: 0,
            object_count: 0,
            last_check: Utc::now(),
        };
        assert!((stats.usage_fraction() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn update_health_stores_stats() {
        let mut manager = LocalSpoolManager::new(default_config()).unwrap();
        let stats = SpoolStats {
            health: SpoolHealth::DiskPressure,
            capacity_bytes: 1000,
            used_bytes: 900,
            object_count: 50,
            last_check: Utc::now(),
        };
        manager.update_health(stats);
        assert_eq!(manager.health(), SpoolHealth::DiskPressure);
        assert!(manager.latest_stats().is_some());
    }
}
