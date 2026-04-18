// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Queue sync types: local-to-central delta sync with conflict resolution.
//!
//! Uses vector clocks for conflict-free replication. When a job is modified
//! both locally and centrally during a partition, the conflict resolution
//! strategy is "last-writer-wins" with the central plane as tiebreaker.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CacheNodeError;

/// A vector clock entry tracking the version at a specific node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    /// Map from node identifier to logical timestamp.
    pub entries: HashMap<String, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Increment the clock for the given node.
    pub fn increment(&mut self, node_id: &str) {
        let counter = self.entries.entry(node_id.to_string()).or_insert(0);
        *counter += 1;
    }

    /// Merge another vector clock into this one, taking the max of each entry.
    pub fn merge(&mut self, other: &Self) {
        for (node, &counter) in &other.entries {
            let entry = self.entries.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(counter);
        }
    }

    /// Determine the causal relationship between two vector clocks.
    #[must_use]
    pub fn compare(&self, other: &Self) -> ClockOrdering {
        let mut self_greater = false;
        let mut other_greater = false;

        let all_keys: std::collections::HashSet<&String> =
            self.entries.keys().chain(other.entries.keys()).collect();

        for key in all_keys {
            let self_val = self.entries.get(key).copied().unwrap_or(0);
            let other_val = other.entries.get(key).copied().unwrap_or(0);

            if self_val > other_val {
                self_greater = true;
            }
            if other_val > self_val {
                other_greater = true;
            }
        }

        match (self_greater, other_greater) {
            (false, false) => ClockOrdering::Equal,
            (true, false) => ClockOrdering::After,
            (false, true) => ClockOrdering::Before,
            (true, true) => ClockOrdering::Concurrent,
        }
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Causal ordering between two vector clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOrdering {
    /// The first clock is causally before the second.
    Before,
    /// The first clock is causally after the second.
    After,
    /// The clocks are equal.
    Equal,
    /// The clocks are concurrent (conflict).
    Concurrent,
}

/// A delta record representing a change to a job during sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDelta {
    /// The job ID that was modified.
    pub job_id: Uuid,
    /// The vector clock at the time of modification.
    pub clock: VectorClock,
    /// The serialized job metadata (JSON).
    pub payload: Vec<u8>,
    /// Timestamp of the modification.
    pub modified_at: DateTime<Utc>,
    /// Identifier of the node that produced this delta.
    pub origin_node: String,
}

/// Outcome of a single job sync operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Local version was newer; pushed to central.
    LocalWins,
    /// Central version was newer; pulled to local.
    CentralWins,
    /// Concurrent modification detected; central wins as tiebreaker.
    ConflictCentralWins,
    /// Versions were identical; no action needed.
    AlreadySynced,
}

/// Result of a full sync session between local and central.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// When the sync session started.
    pub started_at: DateTime<Utc>,
    /// When the sync session completed.
    pub completed_at: DateTime<Utc>,
    /// Number of deltas pushed from local to central.
    pub pushed: u64,
    /// Number of deltas pulled from central to local.
    pub pulled: u64,
    /// Number of conflicts resolved (central wins).
    pub conflicts: u64,
    /// Individual conflict details.
    pub conflict_details: Vec<ConflictRecord>,
}

/// Record of a single sync conflict.
#[derive(Debug, Clone)]
pub struct ConflictRecord {
    /// The job ID with the conflict.
    pub job_id: Uuid,
    /// The local vector clock at the time of conflict.
    pub local_clock: VectorClock,
    /// The central vector clock at the time of conflict.
    pub central_clock: VectorClock,
    /// How the conflict was resolved.
    pub resolution: SyncOutcome,
}

/// Resolve a sync conflict between local and central deltas.
///
/// Central always wins ties (concurrent modifications).
///
/// # Errors
///
/// Returns `CacheNodeError::SyncConflict` when a concurrent modification
/// is detected. The error is informational — the central version is used.
pub fn resolve_conflict(
    local: &SyncDelta,
    central: &SyncDelta,
) -> Result<SyncOutcome, CacheNodeError> {
    let ordering = local.clock.compare(&central.clock);
    match ordering {
        ClockOrdering::After => Ok(SyncOutcome::LocalWins),
        ClockOrdering::Before => Ok(SyncOutcome::CentralWins),
        ClockOrdering::Equal => Ok(SyncOutcome::AlreadySynced),
        ClockOrdering::Concurrent => {
            tracing::warn!(
                job_id = %central.job_id,
                "sync conflict detected: central wins as tiebreaker"
            );
            Err(CacheNodeError::SyncConflict {
                job_id: central.job_id.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_clock_increment() {
        let mut clock = VectorClock::new();
        clock.increment("node-a");
        clock.increment("node-a");
        clock.increment("node-b");
        assert_eq!(clock.entries["node-a"], 2);
        assert_eq!(clock.entries["node-b"], 1);
    }

    #[test]
    fn vector_clock_merge() {
        let mut a = VectorClock::new();
        a.increment("node-a");
        a.increment("node-a");

        let mut b = VectorClock::new();
        b.increment("node-a");
        b.increment("node-b");

        a.merge(&b);
        assert_eq!(a.entries["node-a"], 2);
        assert_eq!(a.entries["node-b"], 1);
    }

    #[test]
    fn vector_clock_compare_equal() {
        let mut a = VectorClock::new();
        a.increment("node-a");
        let mut b = VectorClock::new();
        b.increment("node-a");
        assert_eq!(a.compare(&b), ClockOrdering::Equal);
    }

    #[test]
    fn vector_clock_compare_before() {
        let mut a = VectorClock::new();
        a.increment("node-a");

        let mut b = VectorClock::new();
        b.increment("node-a");
        b.increment("node-a");
        assert_eq!(a.compare(&b), ClockOrdering::Before);
    }

    #[test]
    fn vector_clock_compare_after() {
        let mut a = VectorClock::new();
        a.increment("node-a");
        a.increment("node-a");

        let mut b = VectorClock::new();
        b.increment("node-a");
        assert_eq!(a.compare(&b), ClockOrdering::After);
    }

    #[test]
    fn vector_clock_compare_concurrent() {
        let mut a = VectorClock::new();
        a.increment("node-a");

        let mut b = VectorClock::new();
        b.increment("node-b");
        assert_eq!(a.compare(&b), ClockOrdering::Concurrent);
    }

    #[test]
    fn nist_cp7_central_wins_on_concurrent_conflict() {
        let local = SyncDelta {
            job_id: Uuid::now_v7(),
            clock: {
                let mut c = VectorClock::new();
                c.increment("local");
                c
            },
            payload: vec![1],
            modified_at: Utc::now(),
            origin_node: "local".to_string(),
        };
        let central = SyncDelta {
            job_id: local.job_id,
            clock: {
                let mut c = VectorClock::new();
                c.increment("central");
                c
            },
            payload: vec![2],
            modified_at: Utc::now(),
            origin_node: "central".to_string(),
        };
        let result = resolve_conflict(&local, &central);
        assert!(result.is_err());
        // SyncConflict error indicates central wins.
    }

    #[test]
    fn resolve_local_wins_when_after() {
        let local = SyncDelta {
            job_id: Uuid::now_v7(),
            clock: {
                let mut c = VectorClock::new();
                c.increment("node");
                c.increment("node");
                c
            },
            payload: vec![1],
            modified_at: Utc::now(),
            origin_node: "local".to_string(),
        };
        let central = SyncDelta {
            job_id: local.job_id,
            clock: {
                let mut c = VectorClock::new();
                c.increment("node");
                c
            },
            payload: vec![2],
            modified_at: Utc::now(),
            origin_node: "central".to_string(),
        };
        let result = resolve_conflict(&local, &central).unwrap();
        assert_eq!(result, SyncOutcome::LocalWins);
    }

    #[test]
    fn resolve_already_synced_when_equal() {
        let clock = {
            let mut c = VectorClock::new();
            c.increment("node");
            c
        };
        let local = SyncDelta {
            job_id: Uuid::now_v7(),
            clock: clock.clone(),
            payload: vec![1],
            modified_at: Utc::now(),
            origin_node: "local".to_string(),
        };
        let central = SyncDelta {
            job_id: local.job_id,
            clock,
            payload: vec![1],
            modified_at: Utc::now(),
            origin_node: "central".to_string(),
        };
        let result = resolve_conflict(&local, &central).unwrap();
        assert_eq!(result, SyncOutcome::AlreadySynced);
    }
}
