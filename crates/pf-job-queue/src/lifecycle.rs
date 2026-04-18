// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Explicit state machine for job lifecycle transitions.
//!
//! **NIST 800-53 Rev 5:** AU-2, AU-12 — Every state transition is an
//! auditable event. Invalid transitions return errors (never panic).
//!
//! ```text
//! Held → Waiting → Releasing → Printing → Completed → Purged
//!                                       ↘ Failed    → Purged
//! ```

use std::net::IpAddr;

use chrono::Utc;
use pf_common::audit::{AuditEvent, Auditable, EventKind, Outcome};
use pf_common::identity::Edipi;
use pf_common::job::{JobMetadata, JobStatus};
use uuid::Uuid;

use crate::error::JobQueueError;

/// Represents a successful state transition with the associated audit event.
#[derive(Debug)]
pub struct Transition {
    /// The new status after the transition.
    pub new_status: JobStatus,
    /// The audit event to emit for this transition.
    pub audit_event: AuditEvent,
}

/// Attempt a state transition on a job.
///
/// **NIST 800-53 Rev 5:** AU-2, AU-12 — auditable state transition.
///
/// # Errors
///
/// Returns `JobQueueError::InvalidTransition` if the transition is not
/// permitted by the state machine.
/// Returns `JobQueueError::AlreadyPurged` if the job has been purged.
pub fn transition(
    job: &JobMetadata,
    target: JobStatus,
    actor: &Edipi,
    source_ip: IpAddr,
) -> Result<Transition, JobQueueError> {
    if job.status == JobStatus::Purged {
        return Err(JobQueueError::AlreadyPurged);
    }

    if !is_valid_transition(job.status, target) {
        return Err(JobQueueError::InvalidTransition {
            from: job.status,
            to: target,
        });
    }

    let event_kind = transition_event_kind(target);
    let outcome = Outcome::Success;

    let audit_event = AuditEvent {
        id: Uuid::now_v7(),
        timestamp: Utc::now(),
        actor: actor.clone(),
        action: event_kind,
        target: job.id.as_uuid().to_string(),
        outcome,
        source_ip,
        nist_control: Some("AU-2, AU-12".to_string()),
    };

    Ok(Transition {
        new_status: target,
        audit_event,
    })
}

/// Check whether transitioning from `from` to `to` is valid.
#[must_use]
pub fn is_valid_transition(from: JobStatus, to: JobStatus) -> bool {
    matches!(
        (from, to),
        (JobStatus::Held, JobStatus::Waiting)
            | (JobStatus::Waiting, JobStatus::Releasing)
            | (
                JobStatus::Releasing,
                JobStatus::Printing | JobStatus::Failed
            )
            | (
                JobStatus::Printing,
                JobStatus::Completed | JobStatus::Failed
            )
            | (JobStatus::Completed | JobStatus::Failed, JobStatus::Purged)
    )
}

/// Map a target `JobStatus` to the corresponding `EventKind`.
fn transition_event_kind(status: JobStatus) -> EventKind {
    match status {
        JobStatus::Held => EventKind::JobHeld,
        JobStatus::Waiting | JobStatus::Releasing => EventKind::JobReleased,
        JobStatus::Printing => EventKind::JobPrinting,
        JobStatus::Completed => EventKind::JobCompleted,
        JobStatus::Failed => EventKind::JobFailed,
        JobStatus::Purged => EventKind::JobPurged,
    }
}

/// Domain event for a job state transition, implementing `Auditable`.
#[derive(Debug, Clone)]
pub struct JobTransitionEvent {
    /// The job that transitioned.
    pub job_id: pf_common::job::JobId,
    /// Previous status.
    pub from: JobStatus,
    /// New status.
    pub to: JobStatus,
    /// Actor who triggered the transition.
    pub actor: Edipi,
    /// Source IP of the request.
    pub source_ip: IpAddr,
}

impl Auditable for JobTransitionEvent {
    fn to_audit_event(&self) -> AuditEvent {
        AuditEvent {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            actor: self.actor.clone(),
            action: transition_event_kind(self.to),
            target: self.job_id.as_uuid().to_string(),
            outcome: Outcome::Success,
            source_ip: self.source_ip,
            nist_control: Some("AU-2, AU-12".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pf_common::job::{CostCenter, JobId, PrintOptions};

    use super::*;

    fn test_actor() -> Edipi {
        Edipi::new("1234567890").unwrap()
    }

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn make_job(status: JobStatus) -> JobMetadata {
        JobMetadata {
            id: JobId::generate(),
            owner: test_actor(),
            document_name: "test.pdf".to_string(),
            status,
            options: PrintOptions::default(),
            cost_center: CostCenter::new("CC-001", "Test Unit").unwrap(),
            page_count: Some(5),
            submitted_at: Utc::now(),
            released_at: None,
            completed_at: None,
        }
    }

    // --- Valid transitions ---

    #[test]
    fn nist_au2_held_to_waiting() {
        // NIST 800-53 Rev 5: AU-2 — Event Logging
        let job = make_job(JobStatus::Held);
        let t = transition(&job, JobStatus::Waiting, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Waiting);
    }

    #[test]
    fn nist_au2_waiting_to_releasing() {
        let job = make_job(JobStatus::Waiting);
        let t = transition(&job, JobStatus::Releasing, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Releasing);
    }

    #[test]
    fn nist_au2_releasing_to_printing() {
        let job = make_job(JobStatus::Releasing);
        let t = transition(&job, JobStatus::Printing, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Printing);
    }

    #[test]
    fn nist_au2_releasing_to_failed() {
        let job = make_job(JobStatus::Releasing);
        let t = transition(&job, JobStatus::Failed, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Failed);
    }

    #[test]
    fn nist_au2_printing_to_completed() {
        let job = make_job(JobStatus::Printing);
        let t = transition(&job, JobStatus::Completed, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Completed);
    }

    #[test]
    fn nist_au2_printing_to_failed() {
        let job = make_job(JobStatus::Printing);
        let t = transition(&job, JobStatus::Failed, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Failed);
    }

    #[test]
    fn nist_au2_completed_to_purged() {
        let job = make_job(JobStatus::Completed);
        let t = transition(&job, JobStatus::Purged, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Purged);
    }

    #[test]
    fn nist_au2_failed_to_purged() {
        let job = make_job(JobStatus::Failed);
        let t = transition(&job, JobStatus::Purged, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.new_status, JobStatus::Purged);
    }

    // --- Invalid transitions ---

    #[test]
    fn rejects_held_to_printing() {
        let job = make_job(JobStatus::Held);
        let result = transition(&job, JobStatus::Printing, &test_actor(), test_ip());
        assert!(matches!(
            result,
            Err(JobQueueError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn rejects_completed_to_held() {
        let job = make_job(JobStatus::Completed);
        let result = transition(&job, JobStatus::Held, &test_actor(), test_ip());
        assert!(matches!(
            result,
            Err(JobQueueError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn rejects_transition_on_purged_job() {
        let job = make_job(JobStatus::Purged);
        let result = transition(&job, JobStatus::Held, &test_actor(), test_ip());
        assert!(matches!(result, Err(JobQueueError::AlreadyPurged)));
    }

    #[test]
    fn nist_au12_transition_emits_audit_event() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        let job = make_job(JobStatus::Held);
        let t = transition(&job, JobStatus::Waiting, &test_actor(), test_ip()).unwrap();
        assert_eq!(t.audit_event.action, EventKind::JobReleased);
        assert_eq!(t.audit_event.outcome, Outcome::Success);
        assert!(t.audit_event.nist_control.is_some());
    }

    #[test]
    fn nist_au12_job_transition_event_auditable() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        let evt = JobTransitionEvent {
            job_id: JobId::generate(),
            from: JobStatus::Held,
            to: JobStatus::Waiting,
            actor: test_actor(),
            source_ip: test_ip(),
        };
        let audit = evt.to_audit_event();
        assert_eq!(audit.action, EventKind::JobReleased);
    }

    // --- Exhaustive valid-transition check ---

    #[test]
    fn is_valid_transition_exhaustive_valid() {
        assert!(is_valid_transition(JobStatus::Held, JobStatus::Waiting));
        assert!(is_valid_transition(
            JobStatus::Waiting,
            JobStatus::Releasing
        ));
        assert!(is_valid_transition(
            JobStatus::Releasing,
            JobStatus::Printing
        ));
        assert!(is_valid_transition(JobStatus::Releasing, JobStatus::Failed));
        assert!(is_valid_transition(
            JobStatus::Printing,
            JobStatus::Completed
        ));
        assert!(is_valid_transition(JobStatus::Printing, JobStatus::Failed));
        assert!(is_valid_transition(JobStatus::Completed, JobStatus::Purged));
        assert!(is_valid_transition(JobStatus::Failed, JobStatus::Purged));
    }

    #[test]
    fn is_valid_transition_rejects_same_state() {
        assert!(!is_valid_transition(JobStatus::Held, JobStatus::Held));
        assert!(!is_valid_transition(
            JobStatus::Printing,
            JobStatus::Printing
        ));
    }
}
