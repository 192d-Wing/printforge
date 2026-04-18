// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Firmware lifecycle management for `PrintForge`.
//!
//! This crate manages the complete firmware lifecycle for all managed printers:
//! acquisition from vendor sources, integrity validation, `OCI` registry storage,
//! phased rollout (canary -> staging -> fleet), monitoring, and rollback.
//!
//! **NIST 800-53 Rev 5 Controls:**
//! - SI-2 — Flaw Remediation (firmware patching workflow)
//! - SI-7 — Software, Firmware, and Information Integrity (checksum + signature)
//! - CM-3 — Configuration Change Control (phased rollout with approval gates)
//! - CM-7 — Least Functionality (STIG delta analysis)

#![forbid(unsafe_code)]

pub mod acquisition;
pub mod approval;
pub mod config;
pub mod deployment;
pub mod error;
pub mod monitoring;
pub mod pg_repo;
pub mod pusher_hp;
pub mod pusher_km;
pub mod pusher_lexmark;
pub mod pusher_xerox;
pub mod registry;
pub mod repository;
pub mod rollback;
pub mod rollout;
pub mod validation;

// Re-export primary types for ergonomic imports.
pub use approval::{ApprovalRequest, ApprovalStatus};
pub use config::FirmwareConfig;
pub use deployment::{DeploymentResult, FirmwarePusher, Vendor};
pub use error::FirmwareError;
pub use monitoring::{AnomalyEvaluation, AnomalyVerdict, HealthSample};
pub use registry::{ArtifactMetadata, OciArtifactRef};
pub use rollback::RollbackRecord;
pub use rollout::{Rollout, RolloutPhase, RolloutStatus};
pub use pusher_hp::{HpFirmwarePusher, HpPusherConfig};
pub use pusher_km::{KmFirmwarePusher, KmPusherConfig};
pub use pusher_lexmark::{LexmarkFirmwarePusher, LexmarkPusherConfig};
pub use pusher_xerox::{XeroxFirmwarePusher, XeroxPusherConfig};
pub use validation::{ValidatedFirmware, validate_firmware, verify_checksum};
