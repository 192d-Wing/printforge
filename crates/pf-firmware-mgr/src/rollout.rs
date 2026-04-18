// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Phased firmware rollout: canary (5%) -> staging (25%) -> fleet (100%).
//!
//! **NIST 800-53 Rev 5:** CM-3 — Configuration Change Control
//! Deployments proceed through controlled phases with configurable soak
//! periods. Auto-halts on anomaly detection (error rate > baseline + 2 sigma).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::{PrinterId, PrinterModel};

use crate::config::RolloutConfig;
use crate::error::FirmwareError;
use crate::registry::OciArtifactRef;

/// Current phase of a firmware rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RolloutPhase {
    /// Canary phase: small percentage of fleet (default 5%).
    Canary,
    /// Staging phase: larger subset (default 25%).
    Staging,
    /// Full fleet deployment (100%).
    Fleet,
}

impl std::fmt::Display for RolloutPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canary => write!(f, "canary"),
            Self::Staging => write!(f, "staging"),
            Self::Fleet => write!(f, "fleet"),
        }
    }
}

/// Overall status of a firmware rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RolloutStatus {
    /// Rollout has been created but not yet started.
    Pending,
    /// Currently deploying to the active phase.
    InProgress,
    /// In soak period, monitoring for anomalies.
    Soaking,
    /// Paused due to anomaly or manual intervention.
    Halted,
    /// All phases completed successfully.
    Completed,
    /// Rolled back due to anomaly.
    RolledBack,
    /// Cancelled by an administrator.
    Cancelled,
}

/// A firmware rollout plan tracking phased deployment across the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rollout {
    /// Unique rollout identifier.
    pub id: Uuid,

    /// The firmware artifact being deployed.
    pub artifact: OciArtifactRef,

    /// Target printer model for this rollout.
    pub model: PrinterModel,

    /// Rollout configuration (phase percentages, soak periods).
    pub config: RolloutConfig,

    /// Current phase.
    pub current_phase: RolloutPhase,

    /// Current status.
    pub status: RolloutStatus,

    /// Printers selected for the current phase.
    pub phase_targets: Vec<PrinterId>,

    /// Printers that have been successfully updated in this rollout.
    pub completed_targets: Vec<PrinterId>,

    /// Printers that failed to update.
    pub failed_targets: Vec<PrinterId>,

    /// When the rollout was created.
    pub created_at: DateTime<Utc>,

    /// When the current soak period started (if applicable).
    pub soak_started_at: Option<DateTime<Utc>>,

    /// When the rollout completed or was cancelled.
    pub finished_at: Option<DateTime<Utc>>,
}

impl Rollout {
    /// Create a new rollout in [`RolloutStatus::Pending`] state.
    #[must_use]
    pub fn new(artifact: OciArtifactRef, model: PrinterModel, config: RolloutConfig) -> Self {
        Self {
            id: Uuid::new_v4(),
            artifact,
            model,
            config,
            current_phase: RolloutPhase::Canary,
            status: RolloutStatus::Pending,
            phase_targets: Vec::new(),
            completed_targets: Vec::new(),
            failed_targets: Vec::new(),
            created_at: Utc::now(),
            soak_started_at: None,
            finished_at: None,
        }
    }

    /// Transition to the next rollout phase.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::RolloutInProgress`] if the rollout is not in
    /// a state that allows phase advancement.
    pub fn advance_phase(&mut self) -> Result<RolloutPhase, FirmwareError> {
        if self.status != RolloutStatus::Soaking {
            return Err(FirmwareError::RolloutInProgress {
                rollout_id: self.id,
            });
        }

        let next = match self.current_phase {
            RolloutPhase::Canary => RolloutPhase::Staging,
            RolloutPhase::Staging => RolloutPhase::Fleet,
            RolloutPhase::Fleet => {
                self.status = RolloutStatus::Completed;
                self.finished_at = Some(Utc::now());
                return Ok(RolloutPhase::Fleet);
            }
        };

        self.current_phase = next;
        self.status = RolloutStatus::InProgress;
        self.phase_targets.clear();
        self.soak_started_at = None;

        tracing::info!(
            rollout_id = %self.id,
            phase = %next,
            "rollout advanced to next phase"
        );

        Ok(next)
    }

    /// Return the target fleet percentage for a given phase.
    #[must_use]
    pub fn phase_percentage(&self, phase: RolloutPhase) -> u8 {
        match phase {
            RolloutPhase::Canary => self.config.canary_pct,
            RolloutPhase::Staging => self.config.staging_pct,
            RolloutPhase::Fleet => self.config.fleet_pct,
        }
    }

    /// Return the soak period in hours for the current phase.
    #[must_use]
    pub fn current_soak_hours(&self) -> u64 {
        match self.current_phase {
            RolloutPhase::Canary => self.config.canary_soak_hours,
            RolloutPhase::Staging => self.config.staging_soak_hours,
            RolloutPhase::Fleet => 0, // No soak after full fleet deployment.
        }
    }

    /// Mark the current phase as entering the soak period.
    pub fn enter_soak(&mut self) {
        self.status = RolloutStatus::Soaking;
        self.soak_started_at = Some(Utc::now());
        tracing::info!(
            rollout_id = %self.id,
            phase = %self.current_phase,
            "rollout entered soak period"
        );
    }

    /// Halt the rollout (e.g., due to anomaly detection).
    pub fn halt(&mut self, reason: &str) {
        self.status = RolloutStatus::Halted;
        tracing::warn!(
            rollout_id = %self.id,
            phase = %self.current_phase,
            reason = %reason,
            "rollout halted"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn make_test_rollout() -> Rollout {
        let artifact = OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/hp/laserjet-m612".to_string(),
            tag: "4.11.2.1".to_string(),
            digest: "sha256:abcdef".to_string(),
        };
        let model = PrinterModel {
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
        };
        Rollout::new(artifact, model, RolloutConfig::default())
    }

    #[test]
    fn nist_cm3_rollout_starts_in_canary_pending() {
        // NIST 800-53 Rev 5: CM-3 — Controlled rollout starts in canary
        let rollout = make_test_rollout();
        assert_eq!(rollout.current_phase, RolloutPhase::Canary);
        assert_eq!(rollout.status, RolloutStatus::Pending);
    }

    #[test]
    fn nist_cm3_rollout_phase_percentages_match_config() {
        // NIST 800-53 Rev 5: CM-3 — Phase percentages are configurable
        let rollout = make_test_rollout();
        assert_eq!(rollout.phase_percentage(RolloutPhase::Canary), 5);
        assert_eq!(rollout.phase_percentage(RolloutPhase::Staging), 25);
        assert_eq!(rollout.phase_percentage(RolloutPhase::Fleet), 100);
    }

    #[test]
    fn nist_cm3_rollout_advances_canary_to_staging() {
        // NIST 800-53 Rev 5: CM-3 — Phase advancement after soak
        let mut rollout = make_test_rollout();
        rollout.enter_soak();
        let next = rollout.advance_phase().unwrap();
        assert_eq!(next, RolloutPhase::Staging);
        assert_eq!(rollout.status, RolloutStatus::InProgress);
    }

    #[test]
    fn nist_cm3_rollout_advances_staging_to_fleet() {
        let mut rollout = make_test_rollout();
        rollout.enter_soak();
        rollout.advance_phase().unwrap();
        rollout.enter_soak();
        let next = rollout.advance_phase().unwrap();
        assert_eq!(next, RolloutPhase::Fleet);
    }

    #[test]
    fn nist_cm3_rollout_completes_after_fleet_phase() {
        let mut rollout = make_test_rollout();
        // Canary -> Staging
        rollout.enter_soak();
        rollout.advance_phase().unwrap();
        // Staging -> Fleet
        rollout.enter_soak();
        rollout.advance_phase().unwrap();
        // Fleet completes
        rollout.enter_soak();
        let result = rollout.advance_phase().unwrap();
        assert_eq!(result, RolloutPhase::Fleet);
        assert_eq!(rollout.status, RolloutStatus::Completed);
        assert!(rollout.finished_at.is_some());
    }

    #[test]
    fn rollout_cannot_advance_when_not_soaking() {
        let mut rollout = make_test_rollout();
        let result = rollout.advance_phase();
        assert!(matches!(
            result,
            Err(FirmwareError::RolloutInProgress { .. })
        ));
    }

    #[test]
    fn rollout_halt_sets_halted_status() {
        let mut rollout = make_test_rollout();
        rollout.halt("anomaly detected");
        assert_eq!(rollout.status, RolloutStatus::Halted);
    }

    #[test]
    fn soak_hours_correct_per_phase() {
        let rollout = make_test_rollout();
        assert_eq!(rollout.current_soak_hours(), 72);
    }
}
