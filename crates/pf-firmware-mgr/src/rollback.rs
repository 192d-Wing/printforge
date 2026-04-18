// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Firmware rollback: revert printers to the previous firmware version
//! when anomaly detection fires during a soak period.
//!
//! **NIST 800-53 Rev 5:** CM-3 — Configuration Change Control
//! Rollback MUST be automatic if anomaly detection fires during soak period.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterId;

use crate::monitoring::AnomalyEvaluation;
use crate::registry::OciArtifactRef;
use crate::rollout::RolloutPhase;

/// Reason a rollback was initiated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackReason {
    /// Automatic rollback triggered by anomaly detection.
    AnomalyDetected {
        /// The anomaly evaluation that triggered the rollback.
        evaluation: AnomalyEvaluation,
    },

    /// Manual rollback requested by a `FleetAdmin`.
    ManualRequest {
        /// The admin who requested the rollback.
        requested_by: String,

        /// Free-text justification for the rollback.
        justification: String,
    },
}

/// Status of an individual printer's rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrinterRollbackStatus {
    /// Rollback has not yet been attempted on this printer.
    Pending,

    /// Rollback is in progress.
    InProgress,

    /// Rollback completed successfully.
    Success,

    /// Rollback failed; manual intervention required.
    Failed,
}

/// Rollback status for a single printer within a rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrinterRollbackEntry {
    /// The printer being rolled back.
    pub printer_id: PrinterId,

    /// Current status of this printer's rollback.
    pub status: PrinterRollbackStatus,

    /// Error message if the rollback failed.
    pub error_message: Option<String>,
}

/// A complete rollback operation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Unique rollback identifier.
    pub id: Uuid,

    /// The rollout being rolled back.
    pub rollout_id: Uuid,

    /// The firmware artifact that was deployed (being rolled back from).
    pub from_artifact: OciArtifactRef,

    /// The previous firmware artifact to revert to.
    pub to_artifact: OciArtifactRef,

    /// The phase at which the rollback was triggered.
    pub triggered_at_phase: RolloutPhase,

    /// Why the rollback was initiated.
    pub reason: RollbackReason,

    /// Per-printer rollback status.
    pub printer_statuses: Vec<PrinterRollbackEntry>,

    /// When the rollback was initiated.
    pub initiated_at: DateTime<Utc>,

    /// When the rollback completed (all printers processed).
    pub completed_at: Option<DateTime<Utc>>,
}

impl RollbackRecord {
    /// Create a new rollback record.
    #[must_use]
    pub fn new(
        rollout_id: Uuid,
        from_artifact: OciArtifactRef,
        to_artifact: OciArtifactRef,
        triggered_at_phase: RolloutPhase,
        reason: RollbackReason,
        affected_printers: Vec<PrinterId>,
    ) -> Self {
        let printer_statuses = affected_printers
            .into_iter()
            .map(|printer_id| PrinterRollbackEntry {
                printer_id,
                status: PrinterRollbackStatus::Pending,
                error_message: None,
            })
            .collect();

        Self {
            id: Uuid::new_v4(),
            rollout_id,
            from_artifact,
            to_artifact,
            triggered_at_phase,
            reason,
            printer_statuses,
            initiated_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Check whether all printers have been processed (success or failure).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.printer_statuses.iter().all(|entry| {
            matches!(
                entry.status,
                PrinterRollbackStatus::Success | PrinterRollbackStatus::Failed
            )
        })
    }

    /// Count the number of printers that failed rollback.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.printer_statuses
            .iter()
            .filter(|e| e.status == PrinterRollbackStatus::Failed)
            .count()
    }

    /// Count the number of printers that successfully rolled back.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.printer_statuses
            .iter()
            .filter(|e| e.status == PrinterRollbackStatus::Success)
            .count()
    }

    /// Mark the rollback as complete.
    pub fn mark_complete(&mut self) {
        self.completed_at = Some(Utc::now());
        tracing::info!(
            rollback_id = %self.id,
            rollout_id = %self.rollout_id,
            success_count = self.success_count(),
            failure_count = self.failure_count(),
            "rollback operation completed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::{AnomalyEvaluation, AnomalyVerdict};
    use url::Url;

    fn make_artifact(tag: &str) -> OciArtifactRef {
        OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/hp/m612".to_string(),
            tag: tag.to_string(),
            digest: format!("sha256:{tag}"),
        }
    }

    fn make_rollback() -> RollbackRecord {
        let evaluation = AnomalyEvaluation {
            rollout_id: Uuid::new_v4(),
            verdict: AnomalyVerdict::AnomalyDetected,
            observed_error_rate: 0.5,
            threshold: 0.09,
            sample_count: 20,
            evaluated_at: Utc::now(),
        };

        RollbackRecord::new(
            evaluation.rollout_id,
            make_artifact("4.11.2.1"),
            make_artifact("4.11.1.0"),
            RolloutPhase::Canary,
            RollbackReason::AnomalyDetected { evaluation },
            vec![
                PrinterId::new("PRN-0001").unwrap(),
                PrinterId::new("PRN-0002").unwrap(),
            ],
        )
    }

    #[test]
    fn nist_cm3_rollback_initializes_all_printers_pending() {
        // NIST 800-53 Rev 5: CM-3 — All affected printers are tracked
        let record = make_rollback();
        assert_eq!(record.printer_statuses.len(), 2);
        assert!(
            record
                .printer_statuses
                .iter()
                .all(|e| e.status == PrinterRollbackStatus::Pending)
        );
    }

    #[test]
    fn nist_cm3_rollback_is_not_complete_when_pending() {
        let record = make_rollback();
        assert!(!record.is_complete());
    }

    #[test]
    fn nist_cm3_rollback_is_complete_when_all_processed() {
        let mut record = make_rollback();
        record.printer_statuses[0].status = PrinterRollbackStatus::Success;
        record.printer_statuses[1].status = PrinterRollbackStatus::Failed;
        assert!(record.is_complete());
    }

    #[test]
    fn rollback_counts_successes_and_failures() {
        let mut record = make_rollback();
        record.printer_statuses[0].status = PrinterRollbackStatus::Success;
        record.printer_statuses[1].status = PrinterRollbackStatus::Failed;
        assert_eq!(record.success_count(), 1);
        assert_eq!(record.failure_count(), 1);
    }

    #[test]
    fn mark_complete_sets_timestamp() {
        let mut record = make_rollback();
        assert!(record.completed_at.is_none());
        record.mark_complete();
        assert!(record.completed_at.is_some());
    }
}
