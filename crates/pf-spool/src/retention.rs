// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Retention policy types and purge scheduling.
//!
//! Defines the retention window for spool data and the logic for determining
//! which objects are eligible for purge. The actual purge scheduler runs as
//! a background Tokio task.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Retention policy for a spool object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// When this spool object was stored.
    pub stored_at: DateTime<Utc>,
    /// When this spool object becomes eligible for purge.
    pub expires_at: DateTime<Utc>,
}

impl RetentionPolicy {
    /// Create a retention policy from a storage time and retention duration.
    #[must_use]
    pub fn new(stored_at: DateTime<Utc>, retention: chrono::Duration) -> Self {
        Self {
            stored_at,
            expires_at: stored_at + retention,
        }
    }

    /// Check whether this object is expired (eligible for purge).
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check whether this object is expired relative to a given timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Return the remaining time until expiration, or zero if already expired.
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        let now = Utc::now();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            (self.expires_at - now).to_std().unwrap_or(Duration::ZERO)
        }
    }
}

/// A record of a spool object that is eligible for purge.
#[derive(Debug, Clone)]
pub struct PurgeCandidate {
    /// The job ID string for this spool object.
    pub job_id: String,
    /// When this spool object was stored.
    pub stored_at: DateTime<Utc>,
    /// When this spool object expired.
    pub expired_at: DateTime<Utc>,
}

/// Filter a list of spool expiration timestamps, returning those that are expired.
#[must_use]
pub fn find_expired(candidates: &[(String, DateTime<Utc>, DateTime<Utc>)]) -> Vec<PurgeCandidate> {
    let now = Utc::now();
    candidates
        .iter()
        .filter(|(_, _, expires_at)| now >= *expires_at)
        .map(|(job_id, stored_at, expired_at)| PurgeCandidate {
            job_id: job_id.clone(),
            stored_at: *stored_at,
            expired_at: *expired_at,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn retention_policy_not_expired_when_fresh() {
        let policy = RetentionPolicy::new(Utc::now(), TimeDelta::hours(1));
        assert!(!policy.is_expired());
    }

    #[test]
    fn retention_policy_expired_in_past() {
        let stored = Utc::now() - TimeDelta::hours(2);
        let policy = RetentionPolicy::new(stored, TimeDelta::hours(1));
        assert!(policy.is_expired());
    }

    #[test]
    fn retention_policy_is_expired_at_checks_given_time() {
        let stored = Utc::now();
        let policy = RetentionPolicy::new(stored, TimeDelta::hours(1));

        let before_expiry = stored + TimeDelta::minutes(30);
        let after_expiry = stored + TimeDelta::hours(2);

        assert!(!policy.is_expired_at(before_expiry));
        assert!(policy.is_expired_at(after_expiry));
    }

    #[test]
    fn time_remaining_is_zero_when_expired() {
        let stored = Utc::now() - TimeDelta::hours(2);
        let policy = RetentionPolicy::new(stored, TimeDelta::hours(1));
        assert_eq!(policy.time_remaining(), Duration::ZERO);
    }

    #[test]
    fn find_expired_filters_correctly() {
        let now = Utc::now();
        let candidates = vec![
            (
                "job-1".to_string(),
                now - TimeDelta::hours(3),
                now - TimeDelta::hours(1),
            ),
            ("job-2".to_string(), now, now + TimeDelta::hours(1)),
            (
                "job-3".to_string(),
                now - TimeDelta::hours(5),
                now - TimeDelta::hours(2),
            ),
        ];

        let expired = find_expired(&candidates);
        assert_eq!(expired.len(), 2);
        assert!(expired.iter().any(|c| c.job_id == "job-1"));
        assert!(expired.iter().any(|c| c.job_id == "job-3"));
    }
}
