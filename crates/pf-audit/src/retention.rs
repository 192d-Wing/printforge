// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Retention policy types for audit event lifecycle management.
//!
//! Per `DoD` 5015.02: 365 days online (queryable), 7 years archived
//! (compressed, encrypted).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::RetentionConfig;

/// The lifecycle state of an audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionState {
    /// Record is in the online table and queryable.
    Online,
    /// Record has been moved to the compressed archive.
    Archived,
    /// Record's archive retention has expired (eligible for destruction).
    Expired,
}

/// Determines the retention state for a record given its timestamp and
/// the retention policy.
///
/// **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
/// Audit records are retained per `DoD` policy; this function determines
/// whether a record should be online, archived, or expired.
#[must_use]
pub fn retention_state(
    event_timestamp: DateTime<Utc>,
    now: DateTime<Utc>,
    config: &RetentionConfig,
) -> RetentionState {
    let age_days = (now - event_timestamp).num_days();

    if age_days < 0 {
        // Future-dated events stay online
        return RetentionState::Online;
    }

    // SAFETY: We checked age_days >= 0 above, so this cast is lossless.
    let Ok(age_days) = u64::try_from(age_days) else {
        return RetentionState::Online;
    };
    let online_limit = u64::from(config.online_retention_days);
    let archive_limit = u64::from(config.archive_retention_years) * 365;

    if age_days <= online_limit {
        RetentionState::Online
    } else if age_days <= archive_limit {
        RetentionState::Archived
    } else {
        RetentionState::Expired
    }
}

/// Summary of a retention analysis across a set of records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionSummary {
    /// Number of records currently in the online table.
    pub online_count: u64,
    /// Number of records eligible for archival.
    pub archive_eligible_count: u64,
    /// Number of archived records past their retention period.
    pub expired_count: u64,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::config::RetentionConfig;

    #[test]
    fn recent_event_is_online() {
        let config = RetentionConfig::default();
        let now = Utc::now();
        let event_time = now - Duration::days(30);

        assert_eq!(
            retention_state(event_time, now, &config),
            RetentionState::Online
        );
    }

    #[test]
    fn event_at_366_days_is_archived() {
        let config = RetentionConfig::default();
        let now = Utc::now();
        let event_time = now - Duration::days(366);

        assert_eq!(
            retention_state(event_time, now, &config),
            RetentionState::Archived
        );
    }

    #[test]
    fn event_at_8_years_is_expired() {
        let config = RetentionConfig::default();
        let now = Utc::now();
        let event_time = now - Duration::days(8 * 365);

        assert_eq!(
            retention_state(event_time, now, &config),
            RetentionState::Expired
        );
    }

    #[test]
    fn event_at_exactly_365_days_is_online() {
        let config = RetentionConfig::default();
        let now = Utc::now();
        let event_time = now - Duration::days(365);

        assert_eq!(
            retention_state(event_time, now, &config),
            RetentionState::Online
        );
    }

    #[test]
    fn event_at_exactly_7_years_is_archived() {
        let config = RetentionConfig::default();
        let now = Utc::now();
        let event_time = now - Duration::days(7 * 365);

        assert_eq!(
            retention_state(event_time, now, &config),
            RetentionState::Archived
        );
    }

    #[test]
    fn future_dated_event_is_online() {
        let config = RetentionConfig::default();
        let now = Utc::now();
        let event_time = now + Duration::days(1);

        assert_eq!(
            retention_state(event_time, now, &config),
            RetentionState::Online
        );
    }
}
