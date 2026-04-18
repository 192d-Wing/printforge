// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Printer fleet management and monitoring for `PrintForge`.
//!
//! This crate maintains a comprehensive inventory of all managed printers and
//! continuously monitors their health, status, and supply levels via `SNMPv3`
//! and IPP. It provides the data foundation for alerting, firmware management,
//! supply automation, and the admin dashboard.
//!
//! **NIST 800-53 Rev 5:** CM-8 (System Component Inventory), SI-4 (System Monitoring)

#![forbid(unsafe_code)]

pub mod alerting;
pub mod config;
pub mod discovery;
pub mod error;
pub mod health;
pub mod inventory;
pub mod ipp_probe;
pub mod pg_repo;
pub mod repository;
pub mod service;
pub mod service_impl;
pub mod snmp;
pub mod telemetry;

// Re-export primary types for ergonomic use by dependent crates.
pub use alerting::{AlertCategory, AlertSeverity, FleetAlert};
pub use config::FleetConfig;
pub use discovery::{DiscoveredPrinter, DiscoveryMethod, PrinterLocation};
pub use error::FleetError;
pub use health::{HealthInput, HealthScore, HealthWeights, compute_health_score};
pub use inventory::{
    FleetSummary, PrinterQuery, PrinterRecord, PrinterStatusCounts, PrinterUpdate,
};
pub use repository::PrinterRepository;
pub use service::{FleetService, PrinterDetail, PrinterStatusInfo, PrinterSummary};
pub use service_impl::FleetServiceImpl;
