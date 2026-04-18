// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Print job lifecycle management for `PrintForge`.
//!
//! This crate manages the complete lifecycle of print jobs: IPPS ingestion,
//! metadata extraction, policy evaluation, hold, release, delivery,
//! completion, and purge. It is the central orchestrator of the Follow-Me
//! printing workflow.
//!
//! **NIST 800-53 Rev 5:** AU-2, AU-12, SI-10
//!
//! # Modules
//!
//! - [`config`] — Queue configuration (retention TTL, max spool size, sync interval)
//! - [`error`] — Error types for all job queue operations
//! - [`ingestion`] — IPPS job acceptance, IPP attribute parsing
//! - [`metadata`] — `JobMetadata` construction from IPP attributes
//! - [`lifecycle`] — Explicit state machine with audit events
//! - [`release`] — Job release authorization and logic
//! - [`delivery`] — IPPS client types for sending jobs to printers
//! - [`sync`] — NATS-based sync between edge and central
//! - [`retention`] — Auto-purge of expired jobs
//! - [`repository`] — Persistence trait for job metadata

#![forbid(unsafe_code)]

pub mod config;
pub mod delivery;
pub mod error;
pub mod ingestion;
pub mod lifecycle;
pub mod metadata;
pub mod nats_sync;
pub mod pg_repo;
pub mod release;
pub mod repository;
pub mod retention;
pub mod service;
pub mod service_impl;
pub mod sync;

// Re-export primary types for convenience.
pub use config::JobQueueConfig;
pub use delivery::{DeliveryBackend, DeliveryRequest, DeliveryResult, DeliveryStatus};
pub use error::JobQueueError;
pub use ingestion::{IngestRequest, IngestResult, IppAttributes};
pub use lifecycle::{JobTransitionEvent, Transition, transition};
pub use metadata::build_job_metadata;
pub use nats_sync::NatsSyncBackend;
pub use release::{ReleaseRequest, ReleaseResult, authorize_release};
pub use repository::JobRepository;
pub use retention::{RetentionQuery, RetentionSweepResult, is_eligible_for_purge};
pub use service::{
    AdminJobSummary, JobService, JobStatusCounts, JobSummary, SubmitJobRequest, WasteStats,
};
pub use service_impl::JobServiceImpl;
pub use sync::{JobSyncMessage, SyncBackend, SyncBatchResult, SyncDirection};
