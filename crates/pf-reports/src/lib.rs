// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Report persistence and dispatch for `PrintForge`.
//!
//! Reports are generated asynchronously. The admin dashboard POSTs a request,
//! this crate persists a `Pending` row and returns the id immediately. A
//! worker (not yet implemented) picks up pending rows, writes artifacts to
//! object storage, and transitions to `Ready` / `Failed`. This decouples the
//! admin request from the generation cost, which may be slow or memory-heavy.
//!
//! **NIST 800-53 Rev 5:** AU-2 — Event Logging, AU-12 — Audit Record Generation

#![forbid(unsafe_code)]

pub mod error;
pub mod pg_repo;
pub mod repository;
pub mod service;
pub mod service_impl;
pub mod types;
pub mod worker;

pub use error::ReportError;
pub use pg_repo::PgReportRepository;
pub use repository::ReportRepository;
pub use service::ReportService;
pub use service_impl::ReportServiceImpl;
pub use types::{NewReport, ReportFormat, ReportKind, ReportRecord, ReportState};
pub use worker::{GenerationOutcome, GeneratorFn, ReportWorker};
