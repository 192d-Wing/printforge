// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for the firmware management subsystem.
//!
//! Defines vendor feed URLs, soak periods, maintenance windows, and
//! phase percentages for phased rollouts.

use std::collections::HashMap;

use chrono::NaiveTime;
use serde::{Deserialize, Serialize};
use url::Url;

/// Top-level firmware manager configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareConfig {
    /// Vendor-specific firmware feed configurations.
    pub vendor_feeds: HashMap<String, VendorFeedConfig>,

    /// `OCI` registry endpoint for firmware artifact storage.
    pub registry_url: Url,

    /// Default rollout phase configuration.
    pub rollout: RolloutConfig,

    /// Maintenance window during which firmware deployments are permitted.
    pub maintenance_window: MaintenanceWindow,

    /// Anomaly detection thresholds.
    pub anomaly: AnomalyConfig,
}

/// Configuration for a single vendor firmware feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorFeedConfig {
    /// The vendor name (e.g., "HP", "Xerox", "Lexmark", "KM").
    pub vendor: String,

    /// URL of the vendor firmware feed (`NIPR` only; `None` for `SIPR` air-gap).
    pub feed_url: Option<Url>,

    /// Whether this feed requires authentication.
    pub requires_auth: bool,

    /// Poll interval in seconds for checking new firmware versions.
    pub poll_interval_secs: u64,
}

/// Phased rollout configuration with soak periods.
///
/// **NIST 800-53 Rev 5:** CM-3 — Configuration Change Control
/// Phased deployment ensures controlled rollout with observation periods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutConfig {
    /// Canary phase: percentage of fleet (default 5%).
    pub canary_pct: u8,

    /// Canary soak period in hours (default 72).
    pub canary_soak_hours: u64,

    /// Staging phase: percentage of fleet (default 25%).
    pub staging_pct: u8,

    /// Staging soak period in hours (default 48).
    pub staging_soak_hours: u64,

    /// Fleet phase: percentage of fleet (always 100%).
    pub fleet_pct: u8,
}

impl Default for RolloutConfig {
    fn default() -> Self {
        Self {
            canary_pct: 5,
            canary_soak_hours: 72,
            staging_pct: 25,
            staging_soak_hours: 48,
            fleet_pct: 100,
        }
    }
}

/// Maintenance window defining when firmware deployments are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    /// Start time (UTC) of the maintenance window.
    pub start: NaiveTime,

    /// End time (UTC) of the maintenance window.
    pub end: NaiveTime,

    /// Days of the week when deployments are allowed (0 = Monday, 6 = Sunday).
    pub allowed_days: Vec<u8>,
}

/// Anomaly detection thresholds for post-deployment monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Number of standard deviations above baseline error rate that triggers
    /// an anomaly (default: 2.0).
    pub sigma_threshold: f64,

    /// Minimum number of health samples required before anomaly detection
    /// activates.
    pub min_samples: u32,

    /// Health polling interval in seconds during soak period.
    pub poll_interval_secs: u64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            sigma_threshold: 2.0,
            min_samples: 10,
            poll_interval_secs: 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_config_defaults_match_spec() {
        let cfg = RolloutConfig::default();
        assert_eq!(cfg.canary_pct, 5);
        assert_eq!(cfg.canary_soak_hours, 72);
        assert_eq!(cfg.staging_pct, 25);
        assert_eq!(cfg.staging_soak_hours, 48);
        assert_eq!(cfg.fleet_pct, 100);
    }

    #[test]
    fn anomaly_config_defaults() {
        let cfg = AnomalyConfig::default();
        assert!((cfg.sigma_threshold - 2.0).abs() < f64::EPSILON);
        assert_eq!(cfg.min_samples, 10);
    }

    #[test]
    fn vendor_feed_config_round_trips_json() {
        let cfg = VendorFeedConfig {
            vendor: "HP".to_string(),
            feed_url: Some(Url::parse("https://ftp.hp.com/firmware/feed.json").unwrap()),
            requires_auth: false,
            poll_interval_secs: 3600,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: VendorFeedConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.vendor, "HP");
        assert!(parsed.feed_url.is_some());
    }
}
