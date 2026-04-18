// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Immutable audit log and compliance evidence for `PrintForge`.
//!
//! This crate collects, stores, and exports immutable audit records for all
//! security-relevant events across `PrintForge`. It provides SIEM integration
//! (`CEF` format), `eMASS` artifact generation for RMF controls, and the audit
//! query API for compliance personnel.
//!
//! **NIST 800-53 Rev 5 controls owned:** AU-2, AU-3, AU-6, AU-9, AU-12.

#![forbid(unsafe_code)]

pub mod collector;
pub mod config;
pub mod emass;
pub mod error;
pub mod event_catalog;
pub mod pg_repo;
pub mod query;
pub mod repository;
pub mod retention;
pub mod service;
pub mod service_impl;
pub mod siem_export;
pub mod writer;

// Re-exports for convenience
pub use collector::AuditCollector;
pub use config::AuditConfig;
pub use error::AuditError;
pub use query::{AuditQuery, AuditQueryResult};
pub use repository::AuditRepository;
pub use service::{AuditService, NistEvidenceReport};
pub use service_impl::AuditServiceImpl;
pub use writer::AuditWriter;
