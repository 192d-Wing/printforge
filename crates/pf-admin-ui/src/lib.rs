// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Admin dashboard backend for `PrintForge`.
//!
//! Serves the JSON API consumed by the React SPA admin dashboard.
//! Provides aggregated fleet data, job queue views, reporting endpoints,
//! policy management, alert feeds, and user administration.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Every query is scoped by the requester's
//! role and site assignment. A Site Admin for one installation cannot see
//! another installation's data.

#![forbid(unsafe_code)]

pub mod alerts;
pub mod config;
pub mod dashboard;
pub mod error;
pub mod fleet_view;
pub mod job_view;
pub mod policy_mgmt;
pub mod reports;
pub mod routes;
pub mod scope;
pub mod user_mgmt;
