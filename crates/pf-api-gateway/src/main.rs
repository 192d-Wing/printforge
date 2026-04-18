// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Binary entrypoint for the `PrintForge` API gateway.
//!
//! Initializes structured JSON logging, loads configuration, and starts
//! the Axum server with graceful shutdown support for Kubernetes.

use anyhow::Context;
use tracing::info;

use pf_api_gateway::GatewayConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize centralized telemetry (JSON logging + optional OTLP export).
    pf_common::telemetry::init_telemetry("pf-api-gateway")
        .expect("telemetry init");

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting PrintForge API Gateway"
    );

    // Load configuration from environment variables, falling back to defaults.
    let config = GatewayConfig::from_env()
        .context("failed to load gateway configuration from environment")?;

    info!(listen_addr = %config.listen_addr, "configuration loaded");

    pf_api_gateway::run(config)
        .await
        .map_err(|e| anyhow::anyhow!(e))
        .context("API gateway exited with error")?;

    Ok(())
}
