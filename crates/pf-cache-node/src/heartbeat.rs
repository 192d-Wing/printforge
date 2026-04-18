// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Heartbeat to the central management plane.
//!
//! Sends periodic heartbeats at a configurable interval (default 30 s).
//! Three consecutive failures trigger a `DDIL` mode transition.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::HeartbeatConfig;
use crate::error::CacheNodeError;
use crate::mode::{ModeState, ModeTransition, OperatingMode};

/// Payload sent to the central plane in each heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// The site identifier for this cache node.
    pub site_id: String,
    /// Current operating mode of the cache node.
    pub mode: OperatingMode,
    /// Number of jobs in the local queue.
    pub local_queue_depth: u64,
    /// Number of printers reachable from this installation.
    pub reachable_printers: u32,
    /// Timestamp of this heartbeat.
    pub timestamp: DateTime<Utc>,
}

/// Response from the central plane acknowledging a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Whether the central plane accepted the heartbeat.
    pub accepted: bool,
    /// Central plane timestamp for clock-skew detection.
    pub central_timestamp: DateTime<Utc>,
    /// Optional commands from central (e.g., "force sync", "update config").
    pub directives: Vec<String>,
}

/// Manages the heartbeat lifecycle and mode-state integration.
#[derive(Debug)]
pub struct HeartbeatMonitor {
    /// Heartbeat configuration.
    config: HeartbeatConfig,
    /// Timestamp of the last successful heartbeat.
    last_success: Option<DateTime<Utc>>,
    /// Timestamp of the last heartbeat attempt.
    last_attempt: Option<DateTime<Utc>>,
}

impl HeartbeatMonitor {
    /// Create a new `HeartbeatMonitor` with the given configuration.
    #[must_use]
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            config,
            last_success: None,
            last_attempt: None,
        }
    }

    /// Return the configured heartbeat interval.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.config.interval
    }

    /// Return the configured heartbeat timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Return the timestamp of the last successful heartbeat, if any.
    #[must_use]
    pub fn last_success(&self) -> Option<DateTime<Utc>> {
        self.last_success
    }

    /// Return the timestamp of the last heartbeat attempt, if any.
    #[must_use]
    pub fn last_attempt(&self) -> Option<DateTime<Utc>> {
        self.last_attempt
    }

    /// Record a successful heartbeat and update the mode state.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::InvalidModeTransition` if the resulting
    /// mode transition is invalid (should not occur in normal operation).
    pub fn record_success(
        &mut self,
        mode_state: &mut ModeState,
    ) -> Result<Option<ModeTransition>, CacheNodeError> {
        let now = Utc::now();
        self.last_attempt = Some(now);
        self.last_success = Some(now);
        tracing::debug!("heartbeat success");
        mode_state.heartbeat_success()
    }

    /// Record a failed heartbeat and update the mode state.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::InvalidModeTransition` if the resulting
    /// mode transition is invalid (should not occur in normal operation).
    pub fn record_failure(
        &mut self,
        mode_state: &mut ModeState,
    ) -> Result<Option<ModeTransition>, CacheNodeError> {
        self.last_attempt = Some(Utc::now());
        tracing::warn!("heartbeat failure");
        mode_state.heartbeat_failure()
    }

    /// Calculate how long since the last successful heartbeat.
    /// Returns `None` if no successful heartbeat has been recorded.
    #[must_use]
    pub fn time_since_last_success(&self) -> Option<chrono::Duration> {
        self.last_success.map(|t| Utc::now() - t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_monitor() -> HeartbeatMonitor {
        HeartbeatMonitor::new(HeartbeatConfig::default())
    }

    #[test]
    fn new_monitor_has_no_history() {
        let monitor = default_monitor();
        assert!(monitor.last_success().is_none());
        assert!(monitor.last_attempt().is_none());
    }

    #[test]
    fn nist_cp7_record_success_updates_timestamps() {
        let mut monitor = default_monitor();
        let mut mode_state = ModeState::new(1, 3);
        monitor.record_success(&mut mode_state).unwrap();
        assert!(monitor.last_success().is_some());
        assert!(monitor.last_attempt().is_some());
    }

    #[test]
    fn nist_cp7_three_failures_triggers_ddil() {
        let mut monitor = default_monitor();
        let mut mode_state = ModeState::new(1, 3);
        monitor.record_failure(&mut mode_state).unwrap();
        monitor.record_failure(&mut mode_state).unwrap();
        let transition = monitor.record_failure(&mut mode_state).unwrap();
        assert!(transition.is_some());
        assert_eq!(mode_state.current(), OperatingMode::Ddil);
    }

    #[test]
    fn nist_cp7_success_after_degraded_restores_connected() {
        let mut monitor = default_monitor();
        let mut mode_state = ModeState::new(1, 3);
        monitor.record_failure(&mut mode_state).unwrap();
        assert_eq!(mode_state.current(), OperatingMode::Degraded);
        monitor.record_success(&mut mode_state).unwrap();
        assert_eq!(mode_state.current(), OperatingMode::Connected);
    }

    #[test]
    fn interval_returns_configured_value() {
        let monitor = default_monitor();
        assert_eq!(monitor.interval(), Duration::from_secs(30));
    }

    #[test]
    fn heartbeat_payload_serialization() {
        let payload = HeartbeatPayload {
            site_id: "SITE-001".to_string(),
            mode: OperatingMode::Connected,
            local_queue_depth: 42,
            reachable_printers: 5,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: HeartbeatPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.site_id, "SITE-001");
        assert_eq!(deserialized.local_queue_depth, 42);
    }
}
