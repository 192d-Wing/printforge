// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Audit query engine: filter by actor, action, time range, and outcome.
//!
//! **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, Analysis, and Reporting
//! Provides a structured query API for compliance personnel to search the
//! audit log.

use chrono::{DateTime, Utc};
use pf_common::audit::{AuditEvent, EventKind, Outcome};
use pf_common::identity::Edipi;
use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// A structured query against the audit event store.
///
/// All filter fields are optional; unset fields match all records.
/// Filters are combined with AND semantics.
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Filter by actor EDIPI.
    pub actor: Option<Edipi>,

    /// Filter by event kind(s).
    pub actions: Option<Vec<EventKind>>,

    /// Filter by outcome.
    pub outcome: Option<Outcome>,

    /// Start of the time range (inclusive).
    pub from: Option<DateTime<Utc>>,

    /// End of the time range (exclusive).
    pub to: Option<DateTime<Utc>>,

    /// Filter by target (substring match).
    pub target_contains: Option<String>,

    /// Filter by NIST control ID.
    pub nist_control: Option<String>,

    /// Maximum number of results to return.
    pub limit: Option<u32>,

    /// Offset for pagination.
    pub offset: Option<u32>,
}

impl AuditQuery {
    /// Validate the query parameters.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::InvalidQuery` if:
    /// - `from` is after `to`
    /// - `limit` exceeds the maximum allowed (10,000)
    pub fn validate(&self) -> Result<(), AuditError> {
        if let (Some(from), Some(to)) = (self.from, self.to) {
            if from >= to {
                return Err(AuditError::InvalidQuery {
                    message: "'from' must be before 'to'".to_string(),
                });
            }
        }

        if let Some(limit) = self.limit {
            if limit > 10_000 {
                return Err(AuditError::InvalidQuery {
                    message: "limit must not exceed 10,000".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Apply this query as an in-memory filter on a slice of events.
    ///
    /// Used for testing and the in-memory writer. Production queries
    /// are translated to SQL by the repository layer.
    #[must_use]
    pub fn filter(&self, events: &[AuditEvent]) -> Vec<AuditEvent> {
        let mut results: Vec<AuditEvent> =
            events.iter().filter(|e| self.matches(e)).cloned().collect();

        // Sort by timestamp descending (most recent first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        let offset = self.offset.unwrap_or(0) as usize;
        let limit = self.limit.unwrap_or(1000) as usize;

        results.into_iter().skip(offset).take(limit).collect()
    }

    /// Check whether a single event matches all filters.
    fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(ref actor) = self.actor {
            if event.actor.as_str() != actor.as_str() {
                return false;
            }
        }

        if let Some(ref actions) = self.actions {
            if !actions.contains(&event.action) {
                return false;
            }
        }

        if let Some(outcome) = self.outcome {
            if event.outcome != outcome {
                return false;
            }
        }

        if let Some(from) = self.from {
            if event.timestamp < from {
                return false;
            }
        }

        if let Some(to) = self.to {
            if event.timestamp >= to {
                return false;
            }
        }

        if let Some(ref target) = self.target_contains {
            if !event.target.contains(target.as_str()) {
                return false;
            }
        }

        if let Some(ref control) = self.nist_control {
            match &event.nist_control {
                Some(ec) if ec == control => {}
                _ => return false,
            }
        }

        true
    }
}

/// The result of an audit query, including pagination metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryResult {
    /// The matching events.
    pub events: Vec<AuditEvent>,

    /// Total number of matching records (before pagination).
    pub total_count: u64,

    /// The offset used for this page.
    pub offset: u32,

    /// The limit used for this page.
    pub limit: u32,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{Duration, Utc};
    use pf_common::audit::EventKind;
    use uuid::Uuid;

    use super::*;

    fn make_event(action: EventKind, outcome: Outcome, target: &str) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: Edipi::new("1234567890").unwrap(),
            action,
            target: target.to_string(),
            outcome,
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            nist_control: Some("IA-2".to_string()),
        }
    }

    #[test]
    fn nist_au6_query_filters_by_action() {
        // NIST 800-53 Rev 5: AU-6 — Audit Record Review
        // Evidence: Query engine correctly filters by EventKind
        let events = vec![
            make_event(EventKind::AuthSuccess, Outcome::Success, "portal"),
            make_event(EventKind::AuthFailure, Outcome::Failure, "portal"),
            make_event(EventKind::JobSubmitted, Outcome::Success, "printer-1"),
        ];

        let query = AuditQuery {
            actions: Some(vec![EventKind::AuthSuccess]),
            ..AuditQuery::default()
        };

        let results = query.filter(&events);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, EventKind::AuthSuccess);
    }

    #[test]
    fn nist_au6_query_filters_by_outcome() {
        let events = vec![
            make_event(EventKind::AuthSuccess, Outcome::Success, "portal"),
            make_event(EventKind::AuthFailure, Outcome::Failure, "portal"),
        ];

        let query = AuditQuery {
            outcome: Some(Outcome::Failure),
            ..AuditQuery::default()
        };

        let results = query.filter(&events);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, Outcome::Failure);
    }

    #[test]
    fn nist_au6_query_filters_by_target_substring() {
        let events = vec![
            make_event(EventKind::AuthSuccess, Outcome::Success, "login-portal"),
            make_event(EventKind::JobSubmitted, Outcome::Success, "printer-hp-1"),
        ];

        let query = AuditQuery {
            target_contains: Some("portal".to_string()),
            ..AuditQuery::default()
        };

        let results = query.filter(&events);
        assert_eq!(results.len(), 1);
        assert!(results[0].target.contains("portal"));
    }

    #[test]
    fn query_validates_from_before_to() {
        let now = Utc::now();
        let query = AuditQuery {
            from: Some(now),
            to: Some(now - Duration::hours(1)),
            ..AuditQuery::default()
        };

        assert!(query.validate().is_err());
    }

    #[test]
    fn query_validates_limit_max() {
        let query = AuditQuery {
            limit: Some(10_001),
            ..AuditQuery::default()
        };

        assert!(query.validate().is_err());
    }

    #[test]
    fn query_accepts_valid_params() {
        let now = Utc::now();
        let query = AuditQuery {
            from: Some(now - Duration::hours(1)),
            to: Some(now),
            limit: Some(100),
            ..AuditQuery::default()
        };

        assert!(query.validate().is_ok());
    }

    #[test]
    fn query_pagination_works() {
        let events: Vec<AuditEvent> = (0..5)
            .map(|i| make_event(EventKind::AuthSuccess, Outcome::Success, &format!("t-{i}")))
            .collect();

        let query = AuditQuery {
            limit: Some(2),
            offset: Some(1),
            ..AuditQuery::default()
        };

        let results = query.filter(&events);
        assert_eq!(results.len(), 2);
    }
}
