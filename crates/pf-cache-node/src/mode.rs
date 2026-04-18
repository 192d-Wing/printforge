// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Operating mode management for the cache node.
//!
//! Defines the `OperatingMode` enum (`Connected`, `Degraded`, `DDIL`) and
//! transition logic with validation.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
//! Mode transitions are logged as audit events to satisfy AU-2.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{CacheNodeError, DdilReason};

/// The operating mode of a cache node installation.
///
/// Transitions follow a strict state machine:
/// - `Connected` -> `Degraded` (1 heartbeat failure)
/// - `Degraded` -> `DDIL` (3 consecutive failures)
/// - `DDIL` -> `Connected` (successful heartbeat + `NATS` reconnect)
/// - `Connected` -> `DDIL` (manual override allowed)
/// - `Degraded` -> `Connected` (heartbeat recovered)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatingMode {
    /// Full connectivity to central management plane and `NATS` cluster.
    Connected,
    /// Partial connectivity loss; one or more heartbeats have failed
    /// but the `DDIL` threshold has not yet been reached.
    Degraded,
    /// Disconnected, Disrupted, Intermittent, or Limited connectivity.
    /// The cache node operates autonomously.
    Ddil,
}

impl fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => write!(f, "Connected"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Ddil => write!(f, "DDIL"),
        }
    }
}

/// Record of a mode transition, including timestamp and reason.
#[derive(Debug, Clone)]
pub struct ModeTransition {
    /// The mode before the transition.
    pub from: OperatingMode,
    /// The mode after the transition.
    pub to: OperatingMode,
    /// When the transition occurred.
    pub timestamp: DateTime<Utc>,
    /// Why the transition happened (only populated for `DDIL` entries).
    pub reason: Option<DdilReason>,
}

/// Validate whether a mode transition is permitted.
///
/// # Errors
///
/// Returns `CacheNodeError::InvalidModeTransition` if the transition
/// is not allowed by the state machine.
pub fn validate_transition(from: OperatingMode, to: OperatingMode) -> Result<(), CacheNodeError> {
    let valid = match (from, to) {
        // Same mode is a no-op, always allowed.
        (a, b) if a == b => true,
        // Connected can degrade or jump to DDIL (manual override).
        // Degraded can recover or enter DDIL.
        // DDIL can only return to Connected (after full reconnect).
        (OperatingMode::Connected, OperatingMode::Degraded | OperatingMode::Ddil)
        | (OperatingMode::Degraded, OperatingMode::Connected | OperatingMode::Ddil)
        | (OperatingMode::Ddil, OperatingMode::Connected) => true,
        _ => false,
    };

    if valid {
        Ok(())
    } else {
        Err(CacheNodeError::InvalidModeTransition {
            from: from.to_string(),
            to: to.to_string(),
        })
    }
}

/// Tracks the current operating mode and consecutive heartbeat failure count.
#[derive(Debug)]
pub struct ModeState {
    /// Current operating mode.
    current: OperatingMode,
    /// Number of consecutive heartbeat failures.
    consecutive_failures: u32,
    /// Threshold for entering `Degraded` mode.
    degraded_threshold: u32,
    /// Threshold for entering `DDIL` mode.
    ddil_threshold: u32,
    /// History of mode transitions for audit purposes.
    transitions: Vec<ModeTransition>,
}

impl ModeState {
    /// Create a new `ModeState` starting in `Connected` mode.
    #[must_use]
    pub fn new(degraded_threshold: u32, ddil_threshold: u32) -> Self {
        Self {
            current: OperatingMode::Connected,
            consecutive_failures: 0,
            degraded_threshold,
            ddil_threshold,
            transitions: Vec::new(),
        }
    }

    /// Return the current operating mode.
    #[must_use]
    pub fn current(&self) -> OperatingMode {
        self.current
    }

    /// Return the number of consecutive heartbeat failures.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Return the transition history.
    #[must_use]
    pub fn transitions(&self) -> &[ModeTransition] {
        &self.transitions
    }

    /// Record a successful heartbeat. Resets failure count and may
    /// transition back to `Connected`.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::InvalidModeTransition` if an unexpected
    /// transition would occur (should not happen in normal operation).
    pub fn heartbeat_success(&mut self) -> Result<Option<ModeTransition>, CacheNodeError> {
        self.consecutive_failures = 0;
        if self.current != OperatingMode::Connected {
            return self.transition_to(OperatingMode::Connected, None);
        }
        Ok(None)
    }

    /// Record a heartbeat failure. Increments the failure counter and
    /// may trigger a mode transition.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::InvalidModeTransition` if an unexpected
    /// transition would occur (should not happen in normal operation).
    pub fn heartbeat_failure(&mut self) -> Result<Option<ModeTransition>, CacheNodeError> {
        self.consecutive_failures += 1;
        tracing::warn!(
            consecutive_failures = self.consecutive_failures,
            ddil_threshold = self.ddil_threshold,
            "heartbeat failure recorded"
        );

        if self.consecutive_failures >= self.ddil_threshold && self.current != OperatingMode::Ddil {
            let reason = DdilReason::HeartbeatTimeout {
                consecutive_failures: self.consecutive_failures,
            };
            return self.transition_to(OperatingMode::Ddil, Some(reason));
        }

        if self.consecutive_failures >= self.degraded_threshold
            && self.current == OperatingMode::Connected
        {
            return self.transition_to(OperatingMode::Degraded, None);
        }

        Ok(None)
    }

    /// Manually force a mode transition (e.g., operator override).
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::InvalidModeTransition` if the transition
    /// is not allowed by the state machine.
    pub fn force_transition(
        &mut self,
        to: OperatingMode,
        reason: Option<DdilReason>,
    ) -> Result<Option<ModeTransition>, CacheNodeError> {
        if self.current == to {
            return Ok(None);
        }
        self.transition_to(to, reason)
    }

    fn transition_to(
        &mut self,
        to: OperatingMode,
        reason: Option<DdilReason>,
    ) -> Result<Option<ModeTransition>, CacheNodeError> {
        validate_transition(self.current, to)?;

        let transition = ModeTransition {
            from: self.current,
            to,
            timestamp: Utc::now(),
            reason,
        };

        tracing::info!(
            from = %self.current,
            to = %to,
            reason = ?transition.reason,
            "operating mode transition"
        );

        self.current = to;
        self.transitions.push(transition.clone());
        Ok(Some(transition))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_mode_is_connected() {
        let state = ModeState::new(1, 3);
        assert_eq!(state.current(), OperatingMode::Connected);
    }

    #[test]
    fn nist_cp7_single_failure_enters_degraded() {
        let mut state = ModeState::new(1, 3);
        let transition = state.heartbeat_failure().unwrap();
        assert!(transition.is_some());
        assert_eq!(state.current(), OperatingMode::Degraded);
    }

    #[test]
    fn nist_cp7_three_failures_enters_ddil() {
        let mut state = ModeState::new(1, 3);
        state.heartbeat_failure().unwrap(); // -> Degraded
        state.heartbeat_failure().unwrap(); // still Degraded
        let transition = state.heartbeat_failure().unwrap(); // -> DDIL
        assert!(transition.is_some());
        assert_eq!(state.current(), OperatingMode::Ddil);
    }

    #[test]
    fn nist_cp7_heartbeat_success_restores_connected() {
        let mut state = ModeState::new(1, 3);
        state.heartbeat_failure().unwrap(); // -> Degraded
        let transition = state.heartbeat_success().unwrap();
        assert!(transition.is_some());
        assert_eq!(state.current(), OperatingMode::Connected);
        assert_eq!(state.consecutive_failures(), 0);
    }

    #[test]
    fn nist_cp7_ddil_recovery_to_connected() {
        let mut state = ModeState::new(1, 3);
        for _ in 0..3 {
            state.heartbeat_failure().unwrap();
        }
        assert_eq!(state.current(), OperatingMode::Ddil);
        let transition = state.heartbeat_success().unwrap();
        assert!(transition.is_some());
        assert_eq!(state.current(), OperatingMode::Connected);
    }

    #[test]
    fn nist_cp7_ddil_to_degraded_is_invalid() {
        let result = validate_transition(OperatingMode::Ddil, OperatingMode::Degraded);
        assert!(result.is_err());
    }

    #[test]
    fn nist_cp7_manual_override_connected_to_ddil() {
        let mut state = ModeState::new(1, 3);
        let transition = state
            .force_transition(OperatingMode::Ddil, Some(DdilReason::ManualOverride))
            .unwrap();
        assert!(transition.is_some());
        assert_eq!(state.current(), OperatingMode::Ddil);
    }

    #[test]
    fn nist_cp7_transitions_are_recorded() {
        let mut state = ModeState::new(1, 3);
        state.heartbeat_failure().unwrap();
        state.heartbeat_success().unwrap();
        assert_eq!(state.transitions().len(), 2);
    }

    #[test]
    fn same_mode_transition_is_noop() {
        let result = validate_transition(OperatingMode::Connected, OperatingMode::Connected);
        assert!(result.is_ok());
    }

    #[test]
    fn operating_mode_display() {
        assert_eq!(OperatingMode::Connected.to_string(), "Connected");
        assert_eq!(OperatingMode::Degraded.to_string(), "Degraded");
        assert_eq!(OperatingMode::Ddil.to_string(), "DDIL");
    }
}
