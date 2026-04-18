// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Dashboard-specific configuration: refresh intervals, chart defaults,
//! pagination limits.

use serde::{Deserialize, Serialize};

/// Configuration for the `PrintForge` admin dashboard backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUiConfig {
    /// Interval in seconds between automatic dashboard KPI refreshes.
    pub refresh_interval_secs: u64,

    /// Default number of items per page for paginated list endpoints.
    pub default_page_size: u32,

    /// Maximum number of items per page allowed by the API.
    pub max_page_size: u32,

    /// Default number of days of history shown in charts.
    pub chart_history_days: u32,

    /// Maximum number of concurrent WebSocket connections per instance.
    pub max_websocket_connections: u32,

    /// Number of seconds before an idle WebSocket connection is closed.
    pub websocket_idle_timeout_secs: u64,
}

impl Default for AdminUiConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: 30,
            default_page_size: 25,
            max_page_size: 200,
            chart_history_days: 30,
            max_websocket_connections: 500,
            websocket_idle_timeout_secs: 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let cfg = AdminUiConfig::default();
        assert!(cfg.refresh_interval_secs > 0);
        assert!(cfg.default_page_size > 0);
        assert!(cfg.max_page_size >= cfg.default_page_size);
        assert!(cfg.chart_history_days > 0);
    }

    #[test]
    fn config_roundtrip_json() {
        let cfg = AdminUiConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: AdminUiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.refresh_interval_secs,
            cfg.refresh_interval_secs
        );
        assert_eq!(deserialized.default_page_size, cfg.default_page_size);
    }
}
