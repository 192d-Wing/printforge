// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SCIM` 2.0 implementation (`RFC 7643`, `RFC 7644`).
//!
//! Provides the `SCIM` User resource schema, REST endpoint handlers,
//! filter parsing, and bulk operations for `PrintForge` user provisioning.
//!
//! **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management

pub mod bulk;
pub mod endpoints;
pub mod filter;
pub mod schema;
