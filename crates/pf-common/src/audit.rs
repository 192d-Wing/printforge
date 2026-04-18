// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Audit types: `Auditable` trait, `AuditEvent`, `EventKind`, `Outcome`.
//!
//! **NIST 800-53 Rev 5:** AU-3 — Content of Audit Records
//! Every audit record contains: who, what, when, where, and outcome.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::Edipi;

/// Trait implemented by domain events that produce audit records.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
pub trait Auditable {
    /// Convert this domain event into a structured audit record.
    fn to_audit_event(&self) -> AuditEvent;
}

/// A structured, immutable audit record satisfying NIST AU-3.
///
/// Fields: who (`actor`), what (`action`), when (`timestamp`),
/// where (`source_ip`), outcome (`outcome`), and optional NIST control reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor: Edipi,
    pub action: EventKind,
    pub target: String,
    pub outcome: Outcome,
    pub source_ip: IpAddr,
    pub nist_control: Option<String>,
}

/// Whether the audited operation succeeded or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Success,
    Failure,
}

/// Catalog of all auditable event kinds across `PrintForge`.
///
/// Each variant maps to one or more NIST 800-53 controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    // Authentication (IA-2, AC-7)
    AuthSuccess,
    AuthFailure,
    CertValidationFailure,
    PinLockout,

    // User provisioning (AC-2)
    UserCreated,
    UserUpdated,
    UserSuspended,
    UserReactivated,
    RoleChanged,

    // Job lifecycle (AU-2, AU-12)
    JobSubmitted,
    JobHeld,
    JobReleased,
    JobPrinting,
    JobCompleted,
    JobFailed,
    JobPurged,

    // Spool (SC-28, SC-12)
    SpoolStored,
    SpoolRetrieved,
    SpoolPurged,
    KeyRotated,

    // Fleet (CM-8, SI-4)
    PrinterDiscovered,
    PrinterOnline,
    PrinterOffline,
    PrinterError,
    SupplyCritical,

    // Firmware (SI-2, SI-7, CM-3)
    FirmwareAcquired,
    FirmwareValidated,
    FirmwareApproved,
    FirmwareDeployed,
    FirmwareRollback,

    // Policy (AC-3)
    PolicyAllow,
    PolicyDeny,
    PolicyModify,

    // Accounting (AU-12)
    CostAssigned,
    QuotaUpdated,
    QuotaExceeded,
    ChargebackGenerated,

    // Supply (AU-12)
    ReorderTriggered,
    ReorderApproved,
    ReorderSubmitted,

    // Admin (AC-2, CM-3)
    PolicyChanged,
    PrinterAdded,
    PrinterRemoved,
    QuotaAdjusted,

    // Cache node (CP-7)
    DdilEntered,
    DdilExited,
    SyncStarted,
    SyncCompleted,
    SyncConflict,
}
