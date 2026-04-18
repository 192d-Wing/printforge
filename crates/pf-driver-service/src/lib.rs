// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IPPS` endpoint for workstation drivers.
//!
//! Implements the `IPPS` (IPP over TLS) server that accepts print-job
//! submissions from workstation drivers. Supports both WPP / `IPP` Everywhere
//! (driverless) mode and legacy `PrintForge` MSI driver mode.
//!
//! All connections are `IPPS` — plaintext `IPP` is never accepted.
//!
//! **NIST 800-53 Rev 5:** SC-8 (Transmission Confidentiality),
//! SI-10 (Information Input Validation), IA-2 (Identification & Authentication)

#![forbid(unsafe_code)]

pub mod attributes;
pub mod config;
pub mod error;
pub mod hold;
pub mod ipp_parser;
pub mod ipp_response;
pub mod operations;
pub mod server;
pub mod tls;
pub mod wpp;

// Re-exports for convenience.
pub use config::DriverServiceConfig;
pub use error::DriverServiceError;
pub use server::ServerContext;
