// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Long-running background tasks spawned at server startup.
//!
//! Tasks are only spawned if their corresponding service handle is wired on
//! [`AppState`](crate::AppState). Each task shares a single
//! [`CancellationToken`] so a process shutdown propagates to every tick loop
//! before the runtime drops them.
//!
//! **NIST 800-53 Rev 5:** AU-11 — Audit Record Retention

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::BackgroundConfig;

/// Spawn the alert retention sweep. Runs every
/// [`alert_sweep_interval_secs`](BackgroundConfig::alert_sweep_interval_secs),
/// deleting Resolved alerts whose `resolved_at` is older than
/// [`alert_retention_days`](BackgroundConfig::alert_retention_days).
///
/// Returns `None` when background jobs are disabled via config — callers can
/// ignore the handle in that case. When enabled, callers should retain the
/// handle through shutdown coordination.
#[must_use]
pub fn spawn_alert_retention(
    svc: Arc<dyn pf_fleet_mgr::AlertService>,
    config: &BackgroundConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !config.enabled {
        return None;
    }

    let interval_secs = config.alert_sweep_interval_secs;
    let retention_days = config.alert_retention_days;

    let handle = tokio::spawn(async move {
        info!(
            interval_secs,
            retention_days, "alert retention sweep task started"
        );
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        // Fire once at startup + every interval thereafter. The default Burst
        // skip mode lets the ticker self-correct after a long sweep; we do
        // not want queued ticks to pile up during a slow DB.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cutoff = Utc::now() - chrono::Duration::days(retention_days);
                    match svc.sweep_resolved_before(cutoff).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                info!(deleted, cutoff = %cutoff, "alert retention sweep completed");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "alert retention sweep failed");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("alert retention sweep task shutting down");
                        break;
                    }
                }
            }
        }
    });

    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double for [`AlertService`] used by `disabled_config_returns_none`.
    /// Every method panics — the test's assertion is that disabled config
    /// returns early without touching the service.
    struct NeverCalled;

    impl pf_fleet_mgr::AlertService for NeverCalled {
        fn list_scoped(
            &self,
            _installations: Vec<String>,
            _state_filter: Option<pf_fleet_mgr::AlertState>,
            _limit: u32,
            _offset: u32,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            (Vec<pf_fleet_mgr::StoredAlert>, u64),
                            pf_fleet_mgr::FleetError,
                        >,
                    > + Send,
            >,
        > {
            unreachable!("disabled config should not call list_scoped")
        }
        fn get_by_id(
            &self,
            _id: uuid::Uuid,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<pf_fleet_mgr::StoredAlert, pf_fleet_mgr::FleetError>,
                    > + Send,
            >,
        > {
            unreachable!("disabled config should not call get_by_id")
        }
        fn acknowledge(
            &self,
            _id: uuid::Uuid,
            _by_edipi: String,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<pf_fleet_mgr::StoredAlert, pf_fleet_mgr::FleetError>,
                    > + Send,
            >,
        > {
            unreachable!("disabled config should not call acknowledge")
        }
        fn sweep_resolved_before(
            &self,
            _cutoff: chrono::DateTime<chrono::Utc>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<u64, pf_fleet_mgr::FleetError>> + Send>,
        > {
            unreachable!("disabled config should not sweep")
        }
    }

    #[test]
    fn disabled_config_returns_none_without_spawning() {
        // NIST 800-53 Rev 5: AU-11 — Audit Record Retention
        // Evidence: the scheduler respects the disabled flag so one-shot
        // deployments (migrations, smoke tests) do not accumulate timers.
        let cfg = BackgroundConfig {
            enabled: false,
            ..BackgroundConfig::default()
        };
        let (_tx, rx) = watch::channel(false);
        let handle = spawn_alert_retention(Arc::new(NeverCalled), &cfg, rx);
        assert!(handle.is_none());
    }
}
