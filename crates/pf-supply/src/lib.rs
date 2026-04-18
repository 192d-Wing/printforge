// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Supply chain automation for `PrintForge`.
//!
//! Monitors toner and paper consumable levels across the fleet, predicts
//! depletion dates using consumption trends, triggers automated reorder
//! workflows with configurable approval chains, and integrates with
//! vendor ordering APIs (NIPR) or generates manual requisition forms (SIPR).
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation (supply events),
//! AC-3 — Access Enforcement (approval chain).

#![forbid(unsafe_code)]

pub mod approval;
pub mod config;
pub mod error;
pub mod monitoring;
pub mod pg_repo;
pub mod prediction;
pub mod reorder;
pub mod repository;
pub mod requisition;
pub mod vendor;
pub mod vendor_hp;
pub mod vendor_km;
pub mod vendor_lexmark;
pub mod vendor_xerox;

// Re-exports for convenient access by dependent crates.
pub use approval::{ApprovalDecision, ApprovalLevel, ApprovalRequest};
pub use config::SupplyConfig;
pub use error::SupplyError;
pub use monitoring::{ConsumableKind, ThresholdAlert};
pub use prediction::{DepletionEstimate, LevelReading};
pub use reorder::{ReorderRequest, ReorderStatus, ReorderTrigger};
pub use repository::SupplyRepository;
pub use requisition::{RequisitionForm, RequisitionPriority};
pub use vendor::{SupplyVendor, VendorOrder, VendorOrderStatus};
