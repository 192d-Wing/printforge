// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! CAC PIN validation state machine.
//!
//! **NIST 800-53 Rev 5:** AC-7 — Unsuccessful Logon Attempts
//!
//! Tracks consecutive PIN failures per EDIPI. After `max_attempts`
//! consecutive failures, the account is locked out for `lockout_duration`.
//!
//! In production, the attempt counter MUST be stored in `PostgreSQL`
//! (not in-memory) to persist across restarts and load-balanced instances.

use std::collections::HashMap;
use std::time::Instant;

use pf_common::identity::Edipi;

use crate::config::PinConfig;
use crate::error::AuthError;

/// The current state of a PIN validation attempt for a given user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    /// No failed attempts recorded (or counter was reset after success).
    Clean,
    /// One or more failed attempts, but not yet locked out.
    FailedAttempts {
        /// Number of consecutive failures.
        count: u32,
        /// Remaining attempts before lockout.
        remaining: u32,
    },
    /// Account is locked after exceeding `max_attempts`.
    LockedOut {
        /// When the lockout expires.
        until: Instant,
    },
}

/// Tracks PIN attempt state per user.
///
/// **NIST 800-53 Rev 5:** AC-7 — Unsuccessful Logon Attempts
///
/// This is an in-memory implementation suitable for development and testing.
/// Production deployments MUST use the `PostgreSQL`-backed implementation
/// to ensure persistence across restarts.
pub struct PinTracker {
    config: PinConfig,
    /// Map from EDIPI string to (`failure_count`, `last_failure_time`, `lockout_until`).
    state: HashMap<String, PinRecord>,
}

#[derive(Debug, Clone)]
struct PinRecord {
    failure_count: u32,
    lockout_until: Option<Instant>,
}

impl PinTracker {
    /// Create a new `PinTracker` with the given policy.
    #[must_use]
    pub fn new(config: PinConfig) -> Self {
        Self {
            config,
            state: HashMap::new(),
        }
    }

    /// Get the current PIN state for a user.
    #[must_use]
    pub fn get_state(&self, edipi: &Edipi) -> PinState {
        match self.state.get(edipi.as_str()) {
            None => PinState::Clean,
            Some(record) => {
                if let Some(lockout_until) = record.lockout_until {
                    if Instant::now() < lockout_until {
                        return PinState::LockedOut {
                            until: lockout_until,
                        };
                    }
                    // Lockout has expired — treat as clean.
                    return PinState::Clean;
                }
                if record.failure_count == 0 {
                    PinState::Clean
                } else {
                    PinState::FailedAttempts {
                        count: record.failure_count,
                        remaining: self
                            .config
                            .max_attempts
                            .saturating_sub(record.failure_count),
                    }
                }
            }
        }
    }

    /// Record a successful PIN validation, resetting the failure counter.
    pub fn record_success(&mut self, edipi: &Edipi) {
        self.state.remove(edipi.as_str());
    }

    /// Record a failed PIN attempt.
    ///
    /// **NIST 800-53 Rev 5:** AC-7 — Unsuccessful Logon Attempts
    ///
    /// # Errors
    ///
    /// Returns `AuthError::PinLockout` if this failure exceeds `max_attempts`.
    /// Returns `AuthError::PinInvalid` with remaining attempts otherwise.
    /// Returns `AuthError::PinLockout` if the account is already locked.
    pub fn record_failure(&mut self, edipi: &Edipi) -> Result<(), AuthError> {
        // Check if currently locked out.
        if let PinState::LockedOut { .. } = self.get_state(edipi) {
            return Err(AuthError::PinLockout);
        }

        let record = self
            .state
            .entry(edipi.as_str().to_string())
            .or_insert_with(|| PinRecord {
                failure_count: 0,
                lockout_until: None,
            });

        record.failure_count += 1;

        if record.failure_count >= self.config.max_attempts {
            record.lockout_until = Some(Instant::now() + self.config.lockout_duration);
            return Err(AuthError::PinLockout);
        }

        Err(AuthError::PinInvalid {
            remaining_attempts: self
                .config
                .max_attempts
                .saturating_sub(record.failure_count),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn test_config() -> PinConfig {
        PinConfig {
            max_attempts: 3,
            lockout_duration: Duration::from_secs(30 * 60),
        }
    }

    fn test_edipi() -> Edipi {
        Edipi::new("1234567890").unwrap()
    }

    #[test]
    fn initial_state_is_clean() {
        let tracker = PinTracker::new(test_config());
        assert_eq!(tracker.get_state(&test_edipi()), PinState::Clean);
    }

    #[test]
    fn record_success_resets_counter() {
        let mut tracker = PinTracker::new(test_config());
        let edipi = test_edipi();

        // Record one failure.
        let _ = tracker.record_failure(&edipi);
        assert!(matches!(
            tracker.get_state(&edipi),
            PinState::FailedAttempts {
                count: 1,
                remaining: 2
            }
        ));

        // Successful login resets.
        tracker.record_success(&edipi);
        assert_eq!(tracker.get_state(&edipi), PinState::Clean);
    }

    #[test]
    fn nist_ac7_lockout_after_max_attempts() {
        // NIST 800-53 Rev 5: AC-7 — Unsuccessful Logon Attempts
        // Evidence: Account locks after 3 consecutive PIN failures.
        let mut tracker = PinTracker::new(test_config());
        let edipi = test_edipi();

        // First two failures return PinInvalid with remaining count.
        let result1 = tracker.record_failure(&edipi);
        assert!(matches!(
            result1,
            Err(AuthError::PinInvalid {
                remaining_attempts: 2
            })
        ));

        let result2 = tracker.record_failure(&edipi);
        assert!(matches!(
            result2,
            Err(AuthError::PinInvalid {
                remaining_attempts: 1
            })
        ));

        // Third failure triggers lockout.
        let result3 = tracker.record_failure(&edipi);
        assert!(matches!(result3, Err(AuthError::PinLockout)));

        // Subsequent attempts also return lockout.
        let result4 = tracker.record_failure(&edipi);
        assert!(matches!(result4, Err(AuthError::PinLockout)));
    }

    #[test]
    fn nist_ac7_lockout_state_is_reported() {
        // NIST 800-53 Rev 5: AC-7
        // Evidence: get_state correctly reports LockedOut after max failures.
        let mut tracker = PinTracker::new(test_config());
        let edipi = test_edipi();

        for _ in 0..3 {
            let _ = tracker.record_failure(&edipi);
        }

        assert!(matches!(
            tracker.get_state(&edipi),
            PinState::LockedOut { .. }
        ));
    }

    #[test]
    fn lockout_expires_after_duration() {
        let config = PinConfig {
            max_attempts: 1,
            lockout_duration: Duration::from_millis(1), // Very short for testing.
        };
        let mut tracker = PinTracker::new(config);
        let edipi = test_edipi();

        let _ = tracker.record_failure(&edipi);
        assert!(matches!(
            tracker.get_state(&edipi),
            PinState::LockedOut { .. }
        ));

        // Wait for lockout to expire.
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(tracker.get_state(&edipi), PinState::Clean);
    }

    #[test]
    fn separate_users_have_independent_counters() {
        let mut tracker = PinTracker::new(test_config());
        let user_a = Edipi::new("1234567890").unwrap();
        let user_b = Edipi::new("0987654321").unwrap();

        let _ = tracker.record_failure(&user_a);
        assert!(matches!(
            tracker.get_state(&user_a),
            PinState::FailedAttempts { count: 1, .. }
        ));
        assert_eq!(tracker.get_state(&user_b), PinState::Clean);
    }
}
