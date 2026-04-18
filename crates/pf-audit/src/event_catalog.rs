// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Maps each `EventKind` to its governing NIST 800-53 Rev 5 control(s).
//!
//! **NIST 800-53 Rev 5:** AU-2 — Event Logging
//! This module defines the complete catalog of auditable events and their
//! control traceability, satisfying the AU-2 requirement for a defined
//! set of auditable events.

use pf_common::audit::EventKind;

/// A NIST 800-53 control reference associated with an `EventKind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NistControlMapping {
    /// The NIST 800-53 Rev 5 control identifier (e.g., "IA-2").
    pub control_id: &'static str,

    /// Human-readable control name.
    pub control_name: &'static str,

    /// `CEF` severity (0-10) for SIEM export.
    pub cef_severity: u8,
}

/// Returns the NIST 800-53 Rev 5 control mappings for the given event kind.
///
/// Every `EventKind` maps to at least one NIST control. This function
/// provides traceability from code to compliance requirement.
///
/// **NIST 800-53 Rev 5:** AU-2 — Event Logging
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn nist_controls_for(kind: EventKind) -> &'static [NistControlMapping] {
    match kind {
        // Authentication (IA-2, AC-7)
        EventKind::AuthSuccess | EventKind::AuthFailure => &[NistControlMapping {
            control_id: "IA-2",
            control_name: "Identification and Authentication",
            cef_severity: 5,
        }],
        EventKind::CertValidationFailure => &[NistControlMapping {
            control_id: "IA-5(2)",
            control_name: "PKI-Based Authentication",
            cef_severity: 7,
        }],
        EventKind::PinLockout => &[NistControlMapping {
            control_id: "AC-7",
            control_name: "Unsuccessful Logon Attempts",
            cef_severity: 8,
        }],

        // User provisioning (AC-2)
        EventKind::UserCreated
        | EventKind::UserUpdated
        | EventKind::UserSuspended
        | EventKind::UserReactivated
        | EventKind::RoleChanged => &[NistControlMapping {
            control_id: "AC-2",
            control_name: "Account Management",
            cef_severity: 5,
        }],

        // Job lifecycle, Accounting, Supply (AU-12)
        EventKind::JobSubmitted
        | EventKind::JobHeld
        | EventKind::JobReleased
        | EventKind::JobPrinting
        | EventKind::JobCompleted
        | EventKind::JobFailed
        | EventKind::JobPurged
        | EventKind::CostAssigned
        | EventKind::QuotaUpdated
        | EventKind::QuotaExceeded
        | EventKind::ChargebackGenerated
        | EventKind::ReorderTriggered
        | EventKind::ReorderApproved
        | EventKind::ReorderSubmitted => &[NistControlMapping {
            control_id: "AU-12",
            control_name: "Audit Record Generation",
            cef_severity: 3,
        }],

        // Spool (SC-28, SC-12)
        EventKind::SpoolStored | EventKind::SpoolRetrieved | EventKind::SpoolPurged => {
            &[NistControlMapping {
                control_id: "SC-28",
                control_name: "Protection of Information at Rest",
                cef_severity: 4,
            }]
        }
        EventKind::KeyRotated => &[NistControlMapping {
            control_id: "SC-12",
            control_name: "Cryptographic Key Establishment and Management",
            cef_severity: 6,
        }],

        // Fleet (CM-8, SI-4)
        EventKind::PrinterDiscovered
        | EventKind::PrinterOnline
        | EventKind::PrinterOffline
        | EventKind::PrinterError
        | EventKind::SupplyCritical => &[NistControlMapping {
            control_id: "CM-8",
            control_name: "System Component Inventory",
            cef_severity: 4,
        }],

        // Firmware (SI-7, CM-3)
        EventKind::FirmwareAcquired
        | EventKind::FirmwareValidated
        | EventKind::FirmwareApproved
        | EventKind::FirmwareDeployed => &[NistControlMapping {
            control_id: "SI-7",
            control_name: "Software, Firmware, and Information Integrity",
            cef_severity: 6,
        }],
        EventKind::FirmwareRollback | EventKind::PrinterAdded | EventKind::PrinterRemoved => {
            &[NistControlMapping {
                control_id: "CM-3",
                control_name: "Configuration Change Control",
                cef_severity: 7,
            }]
        }

        // Policy (AC-3)
        EventKind::PolicyAllow | EventKind::PolicyDeny | EventKind::PolicyModify => {
            &[NistControlMapping {
                control_id: "AC-3",
                control_name: "Access Enforcement",
                cef_severity: 5,
            }]
        }

        // Admin (AC-2)
        EventKind::PolicyChanged | EventKind::QuotaAdjusted => &[NistControlMapping {
            control_id: "AC-2",
            control_name: "Account Management",
            cef_severity: 6,
        }],

        // Cache node (CP-7)
        EventKind::DdilEntered
        | EventKind::DdilExited
        | EventKind::SyncStarted
        | EventKind::SyncCompleted
        | EventKind::SyncConflict => &[NistControlMapping {
            control_id: "CP-7",
            control_name: "Alternate Processing Site",
            cef_severity: 5,
        }],
    }
}

/// Returns the primary NIST control ID string for the given event kind.
///
/// This is a convenience wrapper around [`nist_controls_for`] that returns
/// the first (primary) control ID.
#[must_use]
pub fn primary_control_id(kind: EventKind) -> &'static str {
    nist_controls_for(kind)
        .first()
        .map_or("AU-12", |m| m.control_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_au2_every_event_kind_has_control_mapping() {
        // NIST 800-53 Rev 5: AU-2 — Event Logging
        // Evidence: Every EventKind maps to at least one NIST control
        let all_kinds = [
            EventKind::AuthSuccess,
            EventKind::AuthFailure,
            EventKind::CertValidationFailure,
            EventKind::PinLockout,
            EventKind::UserCreated,
            EventKind::UserUpdated,
            EventKind::UserSuspended,
            EventKind::UserReactivated,
            EventKind::RoleChanged,
            EventKind::JobSubmitted,
            EventKind::JobHeld,
            EventKind::JobReleased,
            EventKind::JobPrinting,
            EventKind::JobCompleted,
            EventKind::JobFailed,
            EventKind::JobPurged,
            EventKind::SpoolStored,
            EventKind::SpoolRetrieved,
            EventKind::SpoolPurged,
            EventKind::KeyRotated,
            EventKind::PrinterDiscovered,
            EventKind::PrinterOnline,
            EventKind::PrinterOffline,
            EventKind::PrinterError,
            EventKind::SupplyCritical,
            EventKind::FirmwareAcquired,
            EventKind::FirmwareValidated,
            EventKind::FirmwareApproved,
            EventKind::FirmwareDeployed,
            EventKind::FirmwareRollback,
            EventKind::PolicyAllow,
            EventKind::PolicyDeny,
            EventKind::PolicyModify,
            EventKind::CostAssigned,
            EventKind::QuotaUpdated,
            EventKind::QuotaExceeded,
            EventKind::ChargebackGenerated,
            EventKind::ReorderTriggered,
            EventKind::ReorderApproved,
            EventKind::ReorderSubmitted,
            EventKind::PolicyChanged,
            EventKind::PrinterAdded,
            EventKind::PrinterRemoved,
            EventKind::QuotaAdjusted,
            EventKind::DdilEntered,
            EventKind::DdilExited,
            EventKind::SyncStarted,
            EventKind::SyncCompleted,
            EventKind::SyncConflict,
        ];

        for kind in all_kinds {
            let controls = nist_controls_for(kind);
            assert!(
                !controls.is_empty(),
                "EventKind {kind:?} has no NIST control mapping"
            );
            for control in controls {
                assert!(
                    !control.control_id.is_empty(),
                    "EventKind {kind:?} has empty control ID"
                );
                assert!(
                    control.cef_severity <= 10,
                    "EventKind {kind:?} has invalid CEF severity {}",
                    control.cef_severity
                );
            }
        }
    }

    #[test]
    fn nist_ia2_auth_events_map_to_ia2() {
        let controls = nist_controls_for(EventKind::AuthSuccess);
        assert_eq!(controls[0].control_id, "IA-2");
    }

    #[test]
    fn nist_ac7_pin_lockout_maps_to_ac7() {
        let controls = nist_controls_for(EventKind::PinLockout);
        assert_eq!(controls[0].control_id, "AC-7");
    }

    #[test]
    fn primary_control_id_returns_first_mapping() {
        assert_eq!(primary_control_id(EventKind::AuthSuccess), "IA-2");
        assert_eq!(primary_control_id(EventKind::JobSubmitted), "AU-12");
    }
}
