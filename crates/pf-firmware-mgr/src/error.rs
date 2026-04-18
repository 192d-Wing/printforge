// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-firmware-mgr` crate.
//!
//! **NIST 800-53 Rev 5:** SI-7 — Software, Firmware, and Information Integrity
//! Error variants cover every failure mode in the firmware lifecycle without
//! leaking internal details to API consumers.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during firmware lifecycle operations.
#[derive(Debug, Error)]
pub enum FirmwareError {
    /// Firmware binary failed SHA-256 checksum verification.
    #[error("checksum verification failed for firmware {firmware_id}")]
    ChecksumMismatch {
        /// The firmware record identifier.
        firmware_id: Uuid,
    },

    /// Firmware binary failed code-signing signature verification.
    #[error("signature verification failed for firmware {firmware_id}")]
    SignatureInvalid {
        /// The firmware record identifier.
        firmware_id: Uuid,
    },

    /// Firmware deployment was not approved by a `FleetAdmin`.
    #[error("firmware {firmware_id} has not been approved for deployment")]
    NotApproved {
        /// The firmware record identifier.
        firmware_id: Uuid,
    },

    /// The requested firmware version was not found in the registry.
    #[error("firmware not found: {firmware_id}")]
    NotFound {
        /// The firmware record identifier.
        firmware_id: Uuid,
    },

    /// A rollout is already in progress for the target scope.
    #[error("rollout already in progress: {rollout_id}")]
    RolloutInProgress {
        /// The active rollout identifier.
        rollout_id: Uuid,
    },

    /// Anomaly detected during post-deployment monitoring.
    #[error("anomaly detected during rollout {rollout_id}: {reason}")]
    AnomalyDetected {
        /// The rollout identifier.
        rollout_id: Uuid,
        /// Human-readable description of the anomaly.
        reason: String,
    },

    /// A rollback operation failed.
    #[error("rollback failed for rollout {rollout_id}")]
    RollbackFailed {
        /// The rollout identifier.
        rollout_id: Uuid,
        /// Underlying cause.
        #[source]
        source: Box<FirmwareError>,
    },

    /// Failed to push firmware to a printer via vendor-specific protocol.
    #[error("deployment to printer failed")]
    DeploymentFailed {
        /// Underlying cause (not exposed to clients).
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// `OCI` registry interaction failed.
    #[error("registry operation failed")]
    Registry {
        /// Underlying cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Firmware acquisition (download or media import) failed.
    #[error("firmware acquisition failed")]
    Acquisition {
        /// Underlying cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Database operation failed.
    #[error("database operation failed")]
    Database {
        /// Underlying cause.
        #[source]
        source: sqlx::Error,
    },

    /// Configuration is invalid or missing required fields.
    #[error("configuration error: {message}")]
    Config {
        /// Description of the configuration problem.
        message: String,
    },
}

impl From<sqlx::Error> for FirmwareError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database { source: err }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mismatch_display_does_not_leak_hash() {
        let err = FirmwareError::ChecksumMismatch {
            firmware_id: Uuid::nil(),
        };
        let msg = err.to_string();
        assert!(msg.contains("checksum verification failed"));
        assert!(!msg.contains("sha256"));
    }

    #[test]
    fn deployment_failed_does_not_leak_internal_details() {
        let inner: Box<dyn std::error::Error + Send + Sync> =
            "internal vendor protocol error XYZ-999".into();
        let err = FirmwareError::DeploymentFailed { source: inner };
        // The Display output is generic; internal details are in the source chain only.
        assert_eq!(err.to_string(), "deployment to printer failed");
    }
}
