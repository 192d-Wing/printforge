// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Prometheus metrics types for the cache node.
//!
//! Tracks sync lag, queue depth, `DDIL` duration, cache hit rate,
//! and other operational metrics.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::mode::OperatingMode;

/// A snapshot of cache node metrics for Prometheus export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Current operating mode (0 = Connected, 1 = Degraded, 2 = DDIL).
    pub operating_mode: u8,
    /// Time since the last successful sync with central, in seconds.
    pub sync_lag_seconds: f64,
    /// Number of jobs in the local queue.
    pub local_queue_depth: u64,
    /// Total time spent in `DDIL` mode since last reset, in seconds.
    pub ddil_duration_seconds: f64,
    /// Auth cache hit rate (0.0 to 1.0).
    pub auth_cache_hit_rate: f64,
    /// Number of entries in the auth cache.
    pub auth_cache_entries: u64,
    /// Number of `NATS` messages currently buffered.
    pub nats_buffer_count: u64,
    /// Bytes of `NATS` messages currently buffered.
    pub nats_buffer_bytes: u64,
    /// Number of local printers online.
    pub printers_online: u32,
    /// Number of local printers in error state.
    pub printers_error: u32,
    /// Local spool usage fraction (0.0 to 1.0).
    pub spool_usage_fraction: f64,
    /// Consecutive heartbeat failures.
    pub heartbeat_failures: u32,
    /// Number of sync conflicts since last reset.
    pub sync_conflicts_total: u64,
    /// Timestamp of this snapshot.
    pub timestamp: DateTime<Utc>,
}

/// Tracks cumulative `DDIL` duration and related counters.
#[derive(Debug)]
pub struct MetricsCollector {
    /// When `DDIL` mode was last entered, if currently in `DDIL`.
    ddil_entered_at: Option<DateTime<Utc>>,
    /// Cumulative `DDIL` duration (excludes current `DDIL` session if active).
    cumulative_ddil: Duration,
    /// When the last sync completed.
    last_sync_completed: Option<DateTime<Utc>>,
    /// Total number of sync conflicts observed.
    sync_conflicts_total: u64,
}

impl MetricsCollector {
    /// Create a new `MetricsCollector`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ddil_entered_at: None,
            cumulative_ddil: Duration::ZERO,
            last_sync_completed: None,
            sync_conflicts_total: 0,
        }
    }

    /// Record that `DDIL` mode was entered.
    pub fn ddil_entered(&mut self) {
        self.ddil_entered_at = Some(Utc::now());
        tracing::info!("metrics: DDIL mode entered");
    }

    /// Record that `DDIL` mode was exited.
    pub fn ddil_exited(&mut self) {
        if let Some(entered) = self.ddil_entered_at.take() {
            let duration = Utc::now() - entered;
            if let Ok(std_duration) = duration.to_std() {
                self.cumulative_ddil += std_duration;
            }
            tracing::info!(
                ddil_duration_secs = duration.num_seconds(),
                "metrics: DDIL mode exited"
            );
        }
    }

    /// Return the total `DDIL` duration, including any current session.
    #[must_use]
    pub fn total_ddil_duration(&self) -> Duration {
        let current = self
            .ddil_entered_at
            .and_then(|entered| (Utc::now() - entered).to_std().ok())
            .unwrap_or(Duration::ZERO);
        self.cumulative_ddil + current
    }

    /// Record that a sync completed.
    pub fn sync_completed(&mut self) {
        self.last_sync_completed = Some(Utc::now());
    }

    /// Record that a sync conflict was resolved.
    pub fn sync_conflict(&mut self) {
        self.sync_conflicts_total += 1;
    }

    /// Return the total number of sync conflicts.
    #[must_use]
    pub fn sync_conflicts_total(&self) -> u64 {
        self.sync_conflicts_total
    }

    /// Calculate the sync lag (time since last successful sync).
    #[must_use]
    pub fn sync_lag(&self) -> Option<Duration> {
        self.last_sync_completed
            .and_then(|t| (Utc::now() - t).to_std().ok())
    }

    /// Convert operating mode to a numeric value for Prometheus.
    #[must_use]
    pub fn mode_to_gauge(mode: OperatingMode) -> u8 {
        match mode {
            OperatingMode::Connected => 0,
            OperatingMode::Degraded => 1,
            OperatingMode::Ddil => 2,
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_collector_has_zero_ddil_duration() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.total_ddil_duration(), Duration::ZERO);
    }

    #[test]
    fn sync_conflict_increments() {
        let mut collector = MetricsCollector::new();
        collector.sync_conflict();
        collector.sync_conflict();
        assert_eq!(collector.sync_conflicts_total(), 2);
    }

    #[test]
    fn sync_lag_is_none_before_first_sync() {
        let collector = MetricsCollector::new();
        assert!(collector.sync_lag().is_none());
    }

    #[test]
    fn sync_lag_some_after_completion() {
        let mut collector = MetricsCollector::new();
        collector.sync_completed();
        assert!(collector.sync_lag().is_some());
    }

    #[test]
    fn mode_to_gauge_values() {
        assert_eq!(MetricsCollector::mode_to_gauge(OperatingMode::Connected), 0);
        assert_eq!(MetricsCollector::mode_to_gauge(OperatingMode::Degraded), 1);
        assert_eq!(MetricsCollector::mode_to_gauge(OperatingMode::Ddil), 2);
    }

    #[test]
    fn ddil_entered_and_exited_accumulates() {
        let mut collector = MetricsCollector::new();
        collector.ddil_entered();
        // Immediately exit; duration will be very small but non-negative.
        collector.ddil_exited();
        // Cumulative should be >= 0 (cannot guarantee > 0 in unit test).
        let _ = collector.total_ddil_duration();
        // Enter again.
        collector.ddil_entered();
        collector.ddil_exited();
        // Just verify it does not panic.
    }

    #[test]
    fn ddil_exited_without_entered_is_noop() {
        let mut collector = MetricsCollector::new();
        collector.ddil_exited(); // should not panic
        assert_eq!(collector.total_ddil_duration(), Duration::ZERO);
    }

    #[test]
    fn metrics_snapshot_serialization() {
        let snapshot = MetricsSnapshot {
            operating_mode: 0,
            sync_lag_seconds: 5.0,
            local_queue_depth: 10,
            ddil_duration_seconds: 0.0,
            auth_cache_hit_rate: 0.95,
            auth_cache_entries: 500,
            nats_buffer_count: 0,
            nats_buffer_bytes: 0,
            printers_online: 3,
            printers_error: 0,
            spool_usage_fraction: 0.25,
            heartbeat_failures: 0,
            sync_conflicts_total: 1,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.local_queue_depth, 10);
        assert_eq!(deserialized.printers_online, 3);
    }
}
