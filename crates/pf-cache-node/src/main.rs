// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Binary entrypoint for `pf-cache-node`, the edge deployment unit.
//!
//! Initializes structured JSON logging, loads configuration, creates
//! the [`Orchestrator`], starts the heartbeat monitor and embedded
//! services, and handles `SIGTERM`/`SIGINT` for Kubernetes graceful
//! shutdown.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site

use anyhow::Context;
use tokio::signal;

use pf_cache_node::{CacheNodeConfig, Orchestrator};

/// Load configuration from a JSON file specified by
/// `PF_CACHE_NODE_CONFIG`, or fall back to a default configuration
/// suitable for local development.
fn load_config() -> anyhow::Result<CacheNodeConfig> {
    if let Ok(path) = std::env::var("PF_CACHE_NODE_CONFIG") {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("reading config from {path}"))?;
        let config: CacheNodeConfig =
            serde_json::from_str(&contents).context("parsing cache node config JSON")?;
        Ok(config)
    } else {
        tracing::info!("PF_CACHE_NODE_CONFIG not set, using default configuration");
        Ok(default_config())
    }
}

/// Build a default configuration for local development.
fn default_config() -> CacheNodeConfig {
    use std::path::PathBuf;

    use pf_cache_node::config::{
        AuthCacheConfig, CentralConfig, FleetProxyConfig, HeartbeatConfig, LocalSpoolConfig,
        MetricsConfig,
    };
    use pf_common::config::{NatsConfig, TlsConfig};
    use pf_common::identity::SiteId;

    CacheNodeConfig {
        site_id: SiteId("LOCAL-DEV-001".to_string()),
        central: CentralConfig {
            url: "https://central.printforge.mil".to_string(),
            tls: TlsConfig {
                cert_path: PathBuf::from("/etc/pki/cert.pem"),
                key_path: PathBuf::from("/etc/pki/key.pem"),
                ca_bundle_path: Some(PathBuf::from("/etc/pki/ca-bundle.pem")),
                require_client_cert: true,
            },
        },
        nats: NatsConfig::default(),
        heartbeat: HeartbeatConfig::default(),
        auth_cache: AuthCacheConfig::default(),
        local_spool: LocalSpoolConfig::default(),
        fleet_proxy: FleetProxyConfig::default(),
        metrics: MetricsConfig::default(),
    }
}

/// Wait for a termination signal (`SIGTERM` or `SIGINT`).
///
/// On Kubernetes, the kubelet sends `SIGTERM` to initiate graceful
/// shutdown. Locally, `Ctrl-C` sends `SIGINT`.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("received SIGINT, initiating graceful shutdown");
        }
        () = terminate => {
            tracing::info!("received SIGTERM, initiating graceful shutdown");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize centralized telemetry (JSON logging + optional OTLP export).
    pf_common::telemetry::init_telemetry("pf-cache-node")
        .expect("telemetry init");

    let config = load_config()?;

    // Print startup banner.
    tracing::info!(
        site_id = %config.site_id.0,
        version = env!("CARGO_PKG_VERSION"),
        "PrintForge Cache Node starting"
    );

    let orchestrator =
        Orchestrator::new(config).context("failed to create cache node orchestrator")?;

    tracing::info!(
        site_id = %orchestrator.site_id().0,
        mode = %orchestrator.current_mode(),
        services = orchestrator.services().len(),
        "orchestrator initialized, waiting for shutdown signal"
    );

    // Wait for shutdown signal (SIGTERM / SIGINT).
    shutdown_signal().await;

    tracing::info!(
        site_id = %orchestrator.site_id().0,
        mode = %orchestrator.current_mode(),
        "PrintForge Cache Node shutting down"
    );

    Ok(())
}
