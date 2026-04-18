// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-fleet-mgr` crate.

use pf_common::error::ValidationError;
use thiserror::Error;

/// Errors produced by fleet management operations.
#[derive(Debug, Error)]
pub enum FleetError {
    /// An input validation error (delegated from `pf-common`).
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    /// A printer with the given ID was not found.
    #[error("printer not found")]
    PrinterNotFound,

    /// `SNMPv3` communication failure.
    #[error("SNMP communication failed")]
    SnmpCommunication(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// `SNMPv3` authentication failure.
    #[error("SNMP authentication failed")]
    SnmpAuth,

    /// IPP probe failure.
    #[error("IPP probe failed")]
    IppProbe(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Discovery scan error.
    #[error("discovery scan failed")]
    Discovery(String),

    /// Database persistence error.
    #[error("repository operation failed")]
    Repository(#[source] sqlx::Error),

    /// Telemetry write failure.
    #[error("telemetry write failed")]
    Telemetry(#[source] sqlx::Error),

    /// Alert routing failure.
    #[error("alert routing failed: {0}")]
    AlertRouting(String),

    /// Invalid health score computation input.
    #[error("health score computation failed: {0}")]
    HealthScore(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}
