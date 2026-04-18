// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Cache node orchestrator: the main process that starts embedded services,
//! monitors health, and manages operating mode transitions.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
//! The orchestrator ensures autonomous operation during `DDIL` mode.

use chrono::{DateTime, Utc};
use pf_common::identity::SiteId;
use serde::{Deserialize, Serialize};

use crate::auth_cache::AuthCache;
use crate::config::CacheNodeConfig;
use crate::error::CacheNodeError;
use crate::fleet_proxy::FleetProxy;
use crate::heartbeat::HeartbeatMonitor;
use crate::local_spool::LocalSpoolManager;
use crate::metrics::MetricsCollector;
use crate::mode::{ModeState, OperatingMode};
use crate::nats_leaf::NatsLeafNode;

/// Status of an embedded service managed by the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Service has not been started yet.
    Stopped,
    /// Service is starting up.
    Starting,
    /// Service is running normally.
    Running,
    /// Service is in a degraded state.
    Degraded,
    /// Service has failed.
    Failed,
}

/// Describes an embedded service within the cache node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedService {
    /// Name of the service.
    pub name: String,
    /// Current status.
    pub status: ServiceStatus,
    /// When the service was last checked.
    pub last_check: Option<DateTime<Utc>>,
}

/// Overall health summary of the cache node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorHealth {
    /// The site identifier.
    pub site_id: SiteId,
    /// Current operating mode.
    pub mode: OperatingMode,
    /// Status of each embedded service.
    pub services: Vec<EmbeddedService>,
    /// When this health summary was generated.
    pub timestamp: DateTime<Utc>,
}

/// The main cache node orchestrator.
///
/// Manages the lifecycle of all embedded services and coordinates
/// mode transitions. During `DDIL` mode, the orchestrator ensures
/// that local services continue operating autonomously.
///
/// **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
#[derive(Debug)]
pub struct Orchestrator {
    /// The site identifier for this installation.
    site_id: SiteId,
    /// Operating mode state machine.
    mode_state: ModeState,
    /// Heartbeat monitor for central plane connectivity.
    heartbeat: HeartbeatMonitor,
    /// `NATS` leaf node connection manager.
    nats_leaf: NatsLeafNode,
    /// Authentication cache.
    auth_cache: AuthCache,
    /// Local spool manager.
    local_spool: LocalSpoolManager,
    /// Fleet proxy for local printers.
    fleet_proxy: FleetProxy,
    /// Metrics collector.
    metrics: MetricsCollector,
    /// Status of embedded services.
    services: Vec<EmbeddedService>,
}

impl Orchestrator {
    /// Create a new `Orchestrator` from configuration.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Config` if the configuration is invalid
    /// (e.g., encryption at rest is disabled).
    pub fn new(config: CacheNodeConfig) -> Result<Self, CacheNodeError> {
        let mode_state = ModeState::new(
            config.heartbeat.degraded_threshold,
            config.heartbeat.ddil_threshold,
        );
        let heartbeat = HeartbeatMonitor::new(config.heartbeat);
        let nats_leaf = NatsLeafNode::new();
        let auth_cache = AuthCache::new(&config.auth_cache);
        let local_spool = LocalSpoolManager::new(config.local_spool)?;
        let fleet_proxy = FleetProxy::new(config.fleet_proxy.poll_interval);
        let metrics = MetricsCollector::new();

        let services = vec![
            EmbeddedService {
                name: "job-queue".to_string(),
                status: ServiceStatus::Stopped,
                last_check: None,
            },
            EmbeddedService {
                name: "auth".to_string(),
                status: ServiceStatus::Stopped,
                last_check: None,
            },
            EmbeddedService {
                name: "spool".to_string(),
                status: ServiceStatus::Stopped,
                last_check: None,
            },
            EmbeddedService {
                name: "fleet-mgr".to_string(),
                status: ServiceStatus::Stopped,
                last_check: None,
            },
            EmbeddedService {
                name: "driver-service".to_string(),
                status: ServiceStatus::Stopped,
                last_check: None,
            },
        ];

        tracing::info!(
            site_id = ?config.site_id,
            "cache node orchestrator created"
        );

        Ok(Self {
            site_id: config.site_id,
            mode_state,
            heartbeat,
            nats_leaf,
            auth_cache,
            local_spool,
            fleet_proxy,
            metrics,
            services,
        })
    }

    /// Return the site identifier.
    #[must_use]
    pub fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Return the current operating mode.
    #[must_use]
    pub fn current_mode(&self) -> OperatingMode {
        self.mode_state.current()
    }

    /// Return a reference to the mode state.
    #[must_use]
    pub fn mode_state(&self) -> &ModeState {
        &self.mode_state
    }

    /// Return a mutable reference to the mode state.
    pub fn mode_state_mut(&mut self) -> &mut ModeState {
        &mut self.mode_state
    }

    /// Return a reference to the heartbeat monitor.
    #[must_use]
    pub fn heartbeat(&self) -> &HeartbeatMonitor {
        &self.heartbeat
    }

    /// Return a mutable reference to the heartbeat monitor.
    pub fn heartbeat_mut(&mut self) -> &mut HeartbeatMonitor {
        &mut self.heartbeat
    }

    /// Return a reference to the `NATS` leaf node.
    #[must_use]
    pub fn nats_leaf(&self) -> &NatsLeafNode {
        &self.nats_leaf
    }

    /// Return a mutable reference to the `NATS` leaf node.
    pub fn nats_leaf_mut(&mut self) -> &mut NatsLeafNode {
        &mut self.nats_leaf
    }

    /// Return a reference to the auth cache.
    #[must_use]
    pub fn auth_cache(&self) -> &AuthCache {
        &self.auth_cache
    }

    /// Return a mutable reference to the auth cache.
    pub fn auth_cache_mut(&mut self) -> &mut AuthCache {
        &mut self.auth_cache
    }

    /// Return a reference to the local spool manager.
    #[must_use]
    pub fn local_spool(&self) -> &LocalSpoolManager {
        &self.local_spool
    }

    /// Return a mutable reference to the local spool manager.
    pub fn local_spool_mut(&mut self) -> &mut LocalSpoolManager {
        &mut self.local_spool
    }

    /// Return a reference to the fleet proxy.
    #[must_use]
    pub fn fleet_proxy(&self) -> &FleetProxy {
        &self.fleet_proxy
    }

    /// Return a mutable reference to the fleet proxy.
    pub fn fleet_proxy_mut(&mut self) -> &mut FleetProxy {
        &mut self.fleet_proxy
    }

    /// Return a reference to the metrics collector.
    #[must_use]
    pub fn metrics(&self) -> &MetricsCollector {
        &self.metrics
    }

    /// Return a mutable reference to the metrics collector.
    pub fn metrics_mut(&mut self) -> &mut MetricsCollector {
        &mut self.metrics
    }

    /// Return a reference to the embedded services.
    #[must_use]
    pub fn services(&self) -> &[EmbeddedService] {
        &self.services
    }

    /// Update the status of a named embedded service.
    pub fn update_service_status(&mut self, name: &str, status: ServiceStatus) {
        if let Some(svc) = self.services.iter_mut().find(|s| s.name == name) {
            svc.status = status;
            svc.last_check = Some(Utc::now());
            tracing::debug!(service = name, status = ?status, "service status updated");
        }
    }

    /// Generate a health summary.
    #[must_use]
    pub fn health(&self) -> OrchestratorHealth {
        OrchestratorHealth {
            site_id: self.site_id.clone(),
            mode: self.mode_state.current(),
            services: self.services.clone(),
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pf_common::config::{NatsConfig, TlsConfig};

    use super::*;
    use crate::config::{
        AuthCacheConfig, CacheNodeConfig, CentralConfig, FleetProxyConfig, HeartbeatConfig,
        LocalSpoolConfig, MetricsConfig,
    };

    fn test_config() -> CacheNodeConfig {
        CacheNodeConfig {
            site_id: SiteId("TEST-SITE-001".to_string()),
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

    #[test]
    fn orchestrator_creates_with_valid_config() {
        let orch = Orchestrator::new(test_config()).unwrap();
        assert_eq!(orch.current_mode(), OperatingMode::Connected);
        assert_eq!(orch.site_id().0, "TEST-SITE-001");
    }

    #[test]
    fn orchestrator_has_five_embedded_services() {
        let orch = Orchestrator::new(test_config()).unwrap();
        assert_eq!(orch.services().len(), 5);
    }

    #[test]
    fn update_service_status_changes_service() {
        let mut orch = Orchestrator::new(test_config()).unwrap();
        orch.update_service_status("auth", ServiceStatus::Running);
        let auth_svc = orch.services().iter().find(|s| s.name == "auth").unwrap();
        assert_eq!(auth_svc.status, ServiceStatus::Running);
        assert!(auth_svc.last_check.is_some());
    }

    #[test]
    fn health_returns_current_state() {
        let orch = Orchestrator::new(test_config()).unwrap();
        let health = orch.health();
        assert_eq!(health.mode, OperatingMode::Connected);
        assert_eq!(health.services.len(), 5);
    }

    #[test]
    fn nist_sc28_rejects_unencrypted_spool() {
        let mut config = test_config();
        config.local_spool.encrypt_at_rest = false;
        let result = Orchestrator::new(config);
        assert!(result.is_err());
    }
}
