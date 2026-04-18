// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for the fleet management service.
//!
//! Defines poll intervals, alert thresholds, and `SNMPv3` credential storage.
//! `SNMPv3` credentials use [`secrecy::SecretString`] to prevent accidental
//! logging or serialization of authentication material.

use std::net::IpAddr;
use std::time::Duration;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use pf_common::config::DatabaseConfig;

/// Top-level configuration for the fleet manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Database configuration for printer inventory persistence.
    pub database: DatabaseConfig,

    /// `SNMPv3` credentials for device polling.
    ///
    /// Not serialized — loaded from a secure secrets provider.
    #[serde(skip)]
    pub snmp_credentials: Vec<SnmpV3Credentials>,

    /// Poll interval configuration.
    pub poll_intervals: PollIntervals,

    /// Thresholds for generating alerts.
    pub alert_thresholds: AlertThresholds,

    /// Allowed subnets for discovery scanning.
    ///
    /// **Security:** Discovery scans MUST be restricted to these subnets.
    pub discovery_subnets: Vec<SubnetConfig>,
}

/// `SNMPv3` credentials for authenticating with managed printers.
///
/// All secret fields use [`SecretString`] to prevent logging.
/// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
pub struct SnmpV3Credentials {
    /// Human-readable label for this credential set.
    pub label: String,

    /// `SNMPv3` security name (username).
    pub security_name: String,

    /// Authentication passphrase (SHA-256).
    pub auth_passphrase: SecretString,

    /// Privacy passphrase (AES-128).
    pub privacy_passphrase: SecretString,
}

// Manual Debug impl to prevent leaking secrets.
impl std::fmt::Debug for SnmpV3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnmpV3Credentials")
            .field("label", &self.label)
            .field("security_name", &self.security_name)
            .field("auth_passphrase", &"***REDACTED***")
            .field("privacy_passphrase", &"***REDACTED***")
            .finish()
    }
}

// Manual Clone impl because SecretString does not implement Clone.
impl Clone for SnmpV3Credentials {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            security_name: self.security_name.clone(),
            auth_passphrase: SecretString::from(
                secrecy::ExposeSecret::expose_secret(&self.auth_passphrase).to_string(),
            ),
            privacy_passphrase: SecretString::from(
                secrecy::ExposeSecret::expose_secret(&self.privacy_passphrase).to_string(),
            ),
        }
    }
}

/// Configurable poll intervals for different telemetry categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollIntervals {
    /// How often to poll printer status (default: 60 s).
    #[serde(with = "humantime_serde")]
    pub status: Duration,

    /// How often to poll supply levels (default: 300 s).
    #[serde(with = "humantime_serde")]
    pub supply_levels: Duration,

    /// How often to collect full telemetry (default: 900 s).
    #[serde(with = "humantime_serde")]
    pub full_telemetry: Duration,
}

impl Default for PollIntervals {
    fn default() -> Self {
        Self {
            status: Duration::from_secs(60),
            supply_levels: Duration::from_secs(300),
            full_telemetry: Duration::from_secs(900),
        }
    }
}

/// Thresholds that trigger alerts when breached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Toner percentage below which a warning alert fires.
    pub toner_warning_pct: u8,

    /// Toner percentage below which a critical alert fires.
    pub toner_critical_pct: u8,

    /// Paper percentage below which a warning alert fires.
    pub paper_warning_pct: u8,

    /// Paper percentage below which a critical alert fires.
    pub paper_critical_pct: u8,

    /// Health score below which a degraded alert fires.
    pub health_degraded_score: u8,

    /// Health score below which a critical alert fires.
    pub health_critical_score: u8,

    /// Number of consecutive poll failures before marking a printer offline.
    pub offline_after_failures: u32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            toner_warning_pct: 20,
            toner_critical_pct: 5,
            paper_warning_pct: 15,
            paper_critical_pct: 5,
            health_degraded_score: 60,
            health_critical_score: 30,
            offline_after_failures: 3,
        }
    }
}

/// A subnet that is authorized for printer discovery scanning.
///
/// **Security:** Discovery scans MUST be restricted to configured subnets
/// to prevent unauthorized network reconnaissance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetConfig {
    /// Base address of the subnet.
    pub base_address: IpAddr,

    /// CIDR prefix length (e.g., 24 for a /24).
    pub prefix_len: u8,

    /// Optional installation or site identifier for grouping.
    pub site_id: Option<String>,
}

/// `humantime` serde helper for `Duration` fields.
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

impl PollIntervals {
    /// Constructs [`PollIntervals`] by reading environment variables with
    /// the `PF_FM_` prefix. Falls back to [`Default`] values for any variable
    /// that is not set.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_FM_POLL_INTERVAL_SECS` | `u64` | Status poll interval in seconds |
    /// | `PF_FM_SUPPLY_POLL_INTERVAL_SECS` | `u64` | Supply levels poll interval in seconds |
    /// | `PF_FM_TELEMETRY_INTERVAL_SECS` | `u64` | Full telemetry collection interval in seconds |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        if let Ok(val) = std::env::var("PF_FM_POLL_INTERVAL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_POLL_INTERVAL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            cfg.status = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_FM_SUPPLY_POLL_INTERVAL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_SUPPLY_POLL_INTERVAL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            cfg.supply_levels = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_FM_TELEMETRY_INTERVAL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_TELEMETRY_INTERVAL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            cfg.full_telemetry = Duration::from_secs(secs);
        }

        Ok(cfg)
    }
}

impl AlertThresholds {
    /// Constructs [`AlertThresholds`] by reading environment variables with
    /// the `PF_FM_` prefix. Falls back to [`Default`] values for any variable
    /// that is not set.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_FM_ALERT_THRESHOLD` | `u8` | Alias for `PF_FM_TONER_WARNING_PCT` |
    /// | `PF_FM_TONER_WARNING_PCT` | `u8` | Toner warning threshold percentage |
    /// | `PF_FM_TONER_CRITICAL_PCT` | `u8` | Toner critical threshold percentage |
    /// | `PF_FM_HEALTH_DEGRADED_SCORE` | `u8` | Health score for degraded alert |
    /// | `PF_FM_HEALTH_CRITICAL_SCORE` | `u8` | Health score for critical alert |
    /// | `PF_FM_OFFLINE_AFTER_FAILURES` | `u32` | Poll failures before marking offline |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        // PF_FM_ALERT_THRESHOLD is a convenience alias for toner_warning_pct.
        if let Ok(val) = std::env::var("PF_FM_ALERT_THRESHOLD") {
            cfg.toner_warning_pct = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_ALERT_THRESHOLD".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_FM_TONER_WARNING_PCT") {
            cfg.toner_warning_pct = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_TONER_WARNING_PCT".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_FM_TONER_CRITICAL_PCT") {
            cfg.toner_critical_pct = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_TONER_CRITICAL_PCT".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_FM_HEALTH_DEGRADED_SCORE") {
            cfg.health_degraded_score = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_HEALTH_DEGRADED_SCORE".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_FM_HEALTH_CRITICAL_SCORE") {
            cfg.health_critical_score = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_HEALTH_CRITICAL_SCORE".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_FM_OFFLINE_AFTER_FAILURES") {
            cfg.offline_after_failures = val.parse().map_err(|e| ConfigError {
                var: "PF_FM_OFFLINE_AFTER_FAILURES".to_string(),
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
    fn default_poll_intervals_match_spec() {
        let intervals = PollIntervals::default();
        assert_eq!(intervals.status, Duration::from_secs(60));
        assert_eq!(intervals.supply_levels, Duration::from_secs(300));
        assert_eq!(intervals.full_telemetry, Duration::from_secs(900));
    }

    #[test]
    fn default_alert_thresholds_are_reasonable() {
        let thresholds = AlertThresholds::default();
        assert!(thresholds.toner_critical_pct < thresholds.toner_warning_pct);
        assert!(thresholds.paper_critical_pct < thresholds.paper_warning_pct);
        assert!(thresholds.health_critical_score < thresholds.health_degraded_score);
    }

    #[test]
    fn snmpv3_credentials_debug_redacts_secrets() {
        let creds = SnmpV3Credentials {
            label: "test".to_string(),
            security_name: "admin".to_string(),
            auth_passphrase: SecretString::from("supersecret".to_string()),
            privacy_passphrase: SecretString::from("privatesecret".to_string()),
        };
        let debug_output = format!("{creds:?}");
        assert!(!debug_output.contains("supersecret"));
        assert!(!debug_output.contains("privatesecret"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn poll_intervals_from_env_returns_defaults_when_no_vars_set() {
        // When none of the PF_FM_* vars are set, from_env falls back to defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let cfg = PollIntervals::from_env().expect("from_env should succeed with defaults");
        let default_cfg = PollIntervals::default();
        assert_eq!(cfg.status, default_cfg.status);
        assert_eq!(cfg.supply_levels, default_cfg.supply_levels);
        assert_eq!(cfg.full_telemetry, default_cfg.full_telemetry);
    }

    #[test]
    fn alert_thresholds_from_env_returns_defaults_when_no_vars_set() {
        // When none of the PF_FM_* alert vars are set, from_env falls back to defaults.
        let cfg = AlertThresholds::from_env().expect("from_env should succeed with defaults");
        let default_cfg = AlertThresholds::default();
        assert_eq!(cfg.toner_warning_pct, default_cfg.toner_warning_pct);
        assert_eq!(cfg.toner_critical_pct, default_cfg.toner_critical_pct);
        assert_eq!(cfg.health_degraded_score, default_cfg.health_degraded_score);
    }

    #[test]
    fn config_error_displays_var_and_message() {
        let err = ConfigError {
            var: "PF_FM_POLL_INTERVAL_SECS".to_string(),
            message: "invalid digit found in string".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("PF_FM_POLL_INTERVAL_SECS"));
        assert!(msg.contains("invalid digit"));
    }
}
