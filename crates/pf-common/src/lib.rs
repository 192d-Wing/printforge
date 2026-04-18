// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 `PrintForge` Contributors

//! Shared types, error handling, crypto, and config for `PrintForge`.
//!
//! Every `PrintForge` crate depends on `pf-common`. This crate provides
//! validated newtypes, audit traits, FIPS-safe crypto wrappers, and
//! common configuration structures.

#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod crypto;
pub mod database;
pub mod error;
pub mod fleet;
pub mod identity;
pub mod job;
pub mod policy;
pub mod telemetry;
pub mod time;
pub mod validated;
