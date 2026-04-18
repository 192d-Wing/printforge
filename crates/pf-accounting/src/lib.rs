// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Print cost accounting and chargeback for `PrintForge`.
//!
//! This crate tracks the cost of every print job, assigns costs to
//! organizational cost centers, enforces quota tracking, and generates
//! chargeback reports. It provides the financial data layer for executive
//! dashboards and RM&A (Resource Management & Analysis) reporting.
//!
//! **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
//! Financial events (cost assignment, quota update, chargeback generation)
//! are auditable events.

#![forbid(unsafe_code)]

pub mod chargeback;
pub mod config;
pub mod cost_center;
pub mod cost_model;
pub mod cost_table;
pub mod error;
#[allow(clippy::cast_possible_wrap)]
pub mod pg_repo;
pub mod quota;
pub mod reporting;
pub mod repository;
pub mod service;
pub mod service_impl;

// Re-exports for convenience.
pub use chargeback::{BillingPeriod, ChargebackReport, ChargebackReportBuilder};
pub use config::{AccountingConfig, CostTableConfig};
pub use cost_center::{AssignmentSource, CostCenterAssignment, UserCostProfile};
pub use cost_model::{CostInput, FinishingOptions, JobCost, calculate_job_cost};
pub use cost_table::CostTableRegistry;
pub use error::AccountingError;
pub use quota::{QuotaCounter, QuotaUsageResult};
pub use repository::AccountingRepository;
pub use service::{AccountingService, QuotaStatusResponse};
pub use service_impl::AccountingServiceImpl;
