// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! HTTP/gRPC API gateway for `PrintForge`.
//!
//! Central entry point for all external API traffic. Handles TLS
//! termination, authentication middleware, RBAC authorization, rate
//! limiting, request routing, input validation, and structured error
//! responses. Built on `Axum`.
//!
//! **NIST 800-53 Rev 5 controls:** AC-3, AC-17, SC-8, SI-10, SI-11

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod middleware;
pub mod router;
pub mod routes;
pub mod server;
pub mod validation;

// Re-exports for convenience.
pub use config::GatewayConfig;
pub use error::ApiError;
pub use server::{AppState, run};
