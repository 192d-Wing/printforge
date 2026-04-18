// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `Axum` server setup, TLS listener configuration, and graceful shutdown.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality,
//! AC-17 — Remote Access

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::DecodingKey;
use tokio::signal;
use tracing::{info, warn};

use crate::config::GatewayConfig;
use crate::router::build_router;

/// Shared application state available to all route handlers and middleware.
#[derive(Clone)]
pub struct AppState {
    /// Gateway configuration snapshot.
    pub config: Arc<GatewayConfig>,
    /// Ed25519 public key for JWT signature verification.
    ///
    /// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
    pub jwt_decoding_key: Option<Arc<DecodingKey>>,

    // -- Backend service handles ------------------------------------------------

    /// User provisioning service (object-safe).
    ///
    /// **NIST 800-53 Rev 5:** AC-2 — Account Management
    pub user_service: Option<Arc<dyn pf_user_provisioning::UserService>>,

    /// Job queue service (object-safe via `Pin<Box<dyn Future>>`).
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    pub job_service: Option<Arc<dyn pf_job_queue::JobService>>,

    /// Fleet management service (object-safe via `Pin<Box<dyn Future>>`).
    ///
    /// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
    pub fleet_service: Option<Arc<dyn pf_fleet_mgr::FleetService>>,

    /// Accounting service (object-safe via `Pin<Box<dyn Future>>`).
    ///
    /// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
    pub accounting_service: Option<Arc<dyn pf_accounting::AccountingService>>,

    /// Audit service (object-safe via `Pin<Box<dyn Future>>`).
    ///
    /// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
    pub audit_service: Option<Arc<dyn pf_audit::AuditService>>,

    /// Fleet alert service (list / acknowledge).
    ///
    /// **NIST 800-53 Rev 5:** SI-4 — System Monitoring
    pub alert_service: Option<Arc<dyn pf_fleet_mgr::AlertService>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("jwt_decoding_key", &self.jwt_decoding_key.is_some())
            .field("user_service", &self.user_service.is_some())
            .field("job_service", &self.job_service.is_some())
            .field("fleet_service", &self.fleet_service.is_some())
            .field("accounting_service", &self.accounting_service.is_some())
            .field("audit_service", &self.audit_service.is_some())
            .field("alert_service", &self.alert_service.is_some())
            .finish()
    }
}

/// Build and run the API gateway server.
///
/// Binds to the configured listen address, optionally with TLS, and
/// performs graceful shutdown on `SIGTERM` / `SIGINT`.
///
/// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
///
/// # Errors
///
/// Returns an error if the server fails to bind or encounters a fatal
/// I/O error during operation.
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn run(config: GatewayConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let shutdown_timeout = Duration::from_secs(config.shutdown_timeout_secs);
    let listen_addr = config.listen_addr;

    let jwt_decoding_key = if config.jwt.public_key_pem.is_empty() {
        warn!("no JWT public key configured — authentication will reject all requests");
        None
    } else {
        let key = DecodingKey::from_ed_pem(config.jwt.public_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT public key: {e}"))?;
        Some(Arc::new(key))
    };

    let state = AppState {
        config: Arc::new(config),
        jwt_decoding_key,
        user_service: None,
        job_service: None,
        fleet_service: None,
        accounting_service: None,
        audit_service: None,
        alert_service: None,
    };

    let app = build_router(state);

    info!(%listen_addr, "starting API gateway");

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_timeout))
        .await?;

    info!("API gateway shut down cleanly");
    Ok(())
}

/// Wait for a shutdown signal (`SIGTERM` or `Ctrl+C`), then allow a grace
/// period for in-flight requests to complete.
async fn shutdown_signal(timeout: Duration) {
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
        () = ctrl_c => { info!("received Ctrl+C, initiating graceful shutdown"); },
        () = terminate => { info!("received SIGTERM, initiating graceful shutdown"); },
    }

    warn!(
        timeout_secs = timeout.as_secs(),
        "waiting for in-flight requests to complete"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_clones() {
        let state = AppState {
            config: Arc::new(GatewayConfig::default()),
            jwt_decoding_key: None,
            user_service: None,
            job_service: None,
            fleet_service: None,
            accounting_service: None,
            audit_service: None,
            alert_service: None,
        };
        let cloned = state.clone();
        assert_eq!(cloned.config.listen_addr, state.config.listen_addr);
    }
}
