// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for the `pf-audit` crate.
//!
//! Covers SIEM endpoint settings, retention periods, export format,
//! and database connection parameters.

use serde::{Deserialize, Serialize};

use pf_common::config::DatabaseConfig;

/// Top-level audit subsystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Database connection for the append-only audit store.
    pub database: DatabaseConfig,

    /// SIEM export configuration.
    pub siem: SiemConfig,

    /// Retention policy settings.
    pub retention: RetentionConfig,
}

/// SIEM export endpoint and format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// Whether SIEM export is enabled.
    pub enabled: bool,

    /// The SIEM endpoint URL (e.g., `Splunk` HEC or `Elastic` bulk API).
    ///
    /// Must use TLS — plaintext endpoints are rejected at startup.
    pub endpoint: String,

    /// The export format to use when shipping events.
    pub format: ExportFormat,

    /// Maximum number of events to batch before flushing.
    pub batch_size: usize,

    /// Flush interval in seconds, even if the batch is not full.
    pub flush_interval_secs: u64,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            format: ExportFormat::Cef,
            batch_size: 100,
            flush_interval_secs: 30,
        }
    }
}

/// Supported SIEM export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// `CEF` (Common Event Format) — preferred for `DoD` SIEM integration.
    Cef,
    /// JSON — raw structured JSON export.
    Json,
}

/// Retention policy configuration.
///
/// Per `DoD` 5015.02: 365 days online (queryable), 7 years archived.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Number of days to keep audit events in the online (queryable) table.
    pub online_retention_days: u32,

    /// Number of years to keep archived audit events (compressed, encrypted).
    pub archive_retention_years: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            online_retention_days: 365,
            archive_retention_years: 7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_retention_matches_dod_5015_02() {
        let config = RetentionConfig::default();
        assert_eq!(config.online_retention_days, 365);
        assert_eq!(config.archive_retention_years, 7);
    }

    #[test]
    fn default_siem_is_disabled() {
        let config = SiemConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn retention_config_round_trips_json() {
        let config = RetentionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RetentionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.online_retention_days,
            deserialized.online_retention_days
        );
        assert_eq!(
            config.archive_retention_years,
            deserialized.archive_retention_years
        );
    }
}
