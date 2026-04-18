// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Installation-level edge cache orchestrator for `PrintForge`.
//!
//! The cache node is the edge deployment unit that runs at each DAF
//! installation. It embeds local instances of the job queue, spool
//! store (`RustFS`), auth cache, fleet proxy, and `NATS` leaf node.
//! Provides full Follow-Me printing capability during WAN outages
//! (`DDIL` mode) and syncs with the central management plane when
//! connectivity is available.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site

#![forbid(unsafe_code)]

pub mod auth_cache;
pub mod config;
pub mod error;
pub mod fleet_proxy;
pub mod heartbeat;
pub mod local_spool;
pub mod metrics;
pub mod mode;
pub mod nats_client;
pub mod nats_leaf;
pub mod orchestrator;
pub mod sync;

// Re-exports for convenience.
pub use config::CacheNodeConfig;
pub use error::CacheNodeError;
pub use mode::OperatingMode;
pub use nats_client::NatsClient;
pub use orchestrator::Orchestrator;
