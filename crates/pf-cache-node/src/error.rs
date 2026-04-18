// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-cache-node` crate.

use std::fmt;

use thiserror::Error;

/// Errors that can occur in the cache node subsystem.
#[derive(Debug, Error)]
pub enum CacheNodeError {
    /// Failed to connect to the central management plane.
    #[error("central plane unreachable: {message}")]
    CentralUnreachable {
        /// Human-readable description of the connectivity failure.
        message: String,
    },

    /// `NATS` leaf node connection or messaging failure.
    #[error("NATS error: {message}")]
    Nats {
        /// Human-readable description of the `NATS` failure.
        message: String,
    },

    /// Heartbeat to the central plane failed.
    #[error("heartbeat failed: {message}")]
    HeartbeatFailed {
        /// Human-readable description of why the heartbeat failed.
        message: String,
    },

    /// Invalid operating mode transition was attempted.
    #[error("invalid mode transition: {from} -> {to}")]
    InvalidModeTransition {
        /// The current mode.
        from: String,
        /// The requested mode.
        to: String,
    },

    /// Sync operation between local and central failed.
    #[error("sync failed: {message}")]
    SyncFailed {
        /// Human-readable description of the sync failure.
        message: String,
    },

    /// Sync conflict detected; central wins.
    #[error("sync conflict on job {job_id}: central version wins")]
    SyncConflict {
        /// The job that had conflicting modifications.
        job_id: String,
    },

    /// Authentication cache error (expired, invalid signature, etc.).
    #[error("auth cache error: {message}")]
    AuthCache {
        /// Human-readable description of the auth cache failure.
        message: String,
    },

    /// Local spool (`RustFS`) error.
    #[error("local spool error: {message}")]
    LocalSpool {
        /// Human-readable description of the spool failure.
        message: String,
    },

    /// Fleet proxy error communicating with a local printer.
    #[error("fleet proxy error: {message}")]
    FleetProxy {
        /// Human-readable description of the fleet proxy failure.
        message: String,
    },

    /// Configuration is invalid.
    #[error("configuration error: {message}")]
    Config {
        /// Human-readable description of the configuration problem.
        message: String,
    },
}

/// The reason a `DDIL` mode transition occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DdilReason {
    /// Consecutive heartbeat failures exceeded the threshold.
    HeartbeatTimeout {
        /// Number of consecutive failures that triggered the transition.
        consecutive_failures: u32,
    },
    /// `NATS` connection was lost.
    NatsDisconnect,
    /// Manual operator override.
    ManualOverride,
}

impl fmt::Display for DdilReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeartbeatTimeout {
                consecutive_failures,
            } => write!(f, "heartbeat timeout ({consecutive_failures} failures)"),
            Self::NatsDisconnect => write!(f, "NATS disconnect"),
            Self::ManualOverride => write!(f, "manual override"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_central_unreachable() {
        let err = CacheNodeError::CentralUnreachable {
            message: "connection refused".to_string(),
        };
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn ddil_reason_display_heartbeat_timeout() {
        let reason = DdilReason::HeartbeatTimeout {
            consecutive_failures: 3,
        };
        assert_eq!(reason.to_string(), "heartbeat timeout (3 failures)");
    }

    #[test]
    fn ddil_reason_display_nats_disconnect() {
        let reason = DdilReason::NatsDisconnect;
        assert_eq!(reason.to_string(), "NATS disconnect");
    }
}
