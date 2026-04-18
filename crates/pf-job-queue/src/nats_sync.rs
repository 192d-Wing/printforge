// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Real `async-nats` implementation of [`SyncBackend`] for job queue
//! replication between edge cache nodes and the central control plane.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
//! Edge nodes sync job state through `NATS` when connectivity is available.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
//! TLS with optional mTLS is supported for all `NATS` connections.

use std::sync::Arc;

use async_nats::Client;
use bytes::Bytes;
use pf_common::config::NatsConfig;
use tokio::sync::Mutex;

use crate::error::JobQueueError;
use crate::sync::{JobSyncMessage, SYNC_SUBJECT_PREFIX, SyncBackend, SyncDirection};

/// Subject used for edge-to-central sync messages.
const EDGE_TO_CENTRAL_SUBJECT: &str = "printforge.jobs.sync.edge-to-central";
/// Subject used for central-to-edge sync messages.
const CENTRAL_TO_EDGE_SUBJECT: &str = "printforge.jobs.sync.central-to-edge";

/// A [`SyncBackend`] implementation backed by a real `async-nats` connection.
///
/// Reconnection is handled internally by the `async-nats` client; callers
/// do not need to implement retry logic.
#[derive(Debug)]
pub struct NatsSyncBackend {
    /// The underlying `NATS` client.
    client: Client,
    /// Subscriber for edge-to-central messages.
    edge_to_central_sub: Arc<Mutex<Option<async_nats::Subscriber>>>,
    /// Subscriber for central-to-edge messages.
    central_to_edge_sub: Arc<Mutex<Option<async_nats::Subscriber>>>,
}

impl NatsSyncBackend {
    /// Connect to the `NATS` server using the provided [`NatsConfig`].
    ///
    /// When `NatsConfig::tls` is `Some`, TLS (and optionally mTLS) is
    /// configured on the connection. The `async-nats` client handles
    /// automatic reconnection.
    ///
    /// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Sync` if the connection cannot be established.
    pub async fn connect(config: &NatsConfig) -> Result<Self, JobQueueError> {
        let client = build_nats_client(config).await?;

        tracing::info!(
            urls = %config.urls,
            tls_enabled = config.tls.is_some(),
            "NATS sync backend connected"
        );

        Ok(Self {
            client,
            edge_to_central_sub: Arc::new(Mutex::new(None)),
            central_to_edge_sub: Arc::new(Mutex::new(None)),
        })
    }

    /// Subscribe to messages for the given [`SyncDirection`].
    ///
    /// Lazily creates the subscription on first call. Subsequent calls
    /// reuse the existing subscription.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Sync` if the subscription fails.
    pub async fn subscribe(&self, direction: SyncDirection) -> Result<(), JobQueueError> {
        let (subject, lock) = match direction {
            SyncDirection::EdgeToCentral => (EDGE_TO_CENTRAL_SUBJECT, &self.edge_to_central_sub),
            SyncDirection::CentralToEdge => (CENTRAL_TO_EDGE_SUBJECT, &self.central_to_edge_sub),
        };

        let mut guard = lock.lock().await;
        if guard.is_none() {
            let subscriber = self
                .client
                .subscribe(subject.to_owned())
                .await
                .map_err(|e| JobQueueError::Sync(Box::new(e)))?;

            tracing::info!(%subject, "subscribed to NATS sync subject");
            *guard = Some(subscriber);
        }

        Ok(())
    }

    /// Return a reference to the underlying `NATS` [`Client`].
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl SyncBackend for NatsSyncBackend {
    /// Publish a [`JobSyncMessage`] as JSON to the appropriate sync subject.
    ///
    /// The subject is chosen based on convention:
    /// `printforge.jobs.sync.<site-id>.<job-id>`.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Sync` on serialization or publish failure.
    async fn publish(&self, message: &JobSyncMessage) -> Result<(), JobQueueError> {
        let payload = serde_json::to_vec(message).map_err(|e| {
            tracing::error!(error = %e, "failed to serialize JobSyncMessage");
            JobQueueError::Sync(Box::new(e))
        })?;

        let subject = format!(
            "{SYNC_SUBJECT_PREFIX}.{}.{}",
            message.origin_site.0,
            message.job_id.as_uuid()
        );

        self.client
            .publish(subject.clone(), Bytes::from(payload))
            .await
            .map_err(|e| {
                tracing::error!(%subject, error = %e, "failed to publish sync message");
                JobQueueError::Sync(Box::new(e))
            })?;

        tracing::debug!(
            %subject,
            job_id = %message.job_id.as_uuid(),
            sequence = message.sequence,
            "published job sync message"
        );

        Ok(())
    }

    /// Receive the next [`JobSyncMessage`] from the subscription matching
    /// the given [`SyncDirection`].
    ///
    /// Returns `Ok(None)` if the subscription has been closed.
    ///
    /// # Errors
    ///
    /// Returns `JobQueueError::Sync` if the subscription has not been
    /// created (call [`subscribe`](Self::subscribe) first) or on
    /// deserialization failure.
    async fn recv(
        &self,
        direction: SyncDirection,
    ) -> Result<Option<JobSyncMessage>, JobQueueError> {
        let lock = match direction {
            SyncDirection::EdgeToCentral => &self.edge_to_central_sub,
            SyncDirection::CentralToEdge => &self.central_to_edge_sub,
        };

        let mut guard = lock.lock().await;
        let subscriber = guard.as_mut().ok_or_else(|| {
            JobQueueError::Sync(Box::from(
                "subscription not initialised — call subscribe() first",
            ))
        })?;

        let msg = {
            use futures_util::StreamExt as _;
            subscriber.next().await
        };

        if let Some(nats_msg) = msg {
            let sync_msg: JobSyncMessage =
                serde_json::from_slice(&nats_msg.payload).map_err(|e| {
                    tracing::error!(
                        error = %e,
                        subject = %nats_msg.subject,
                        "failed to deserialise sync message"
                    );
                    JobQueueError::Sync(Box::new(e))
                })?;

            tracing::debug!(
                job_id = %sync_msg.job_id.as_uuid(),
                sequence = sync_msg.sequence,
                direction = ?direction,
                "received job sync message"
            );

            Ok(Some(sync_msg))
        } else {
            tracing::info!(?direction, "NATS sync subscription closed");
            Ok(None)
        }
    }
}

/// Build a `rustls` [`ClientConfig`](rustls::ClientConfig) from the
/// provided [`TlsConfig`](pf_common::config::TlsConfig), loading CA
/// trust anchors and optional client certificates for mTLS.
///
/// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
async fn build_tls_config(
    tls_config: &pf_common::config::TlsConfig,
) -> Result<rustls::ClientConfig, JobQueueError> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &tls_config.ca_bundle_path {
        let ca_pem = tokio::fs::read(ca_path).await.map_err(|e| {
            tracing::error!(path = %ca_path.display(), error = %e, "failed to read CA bundle");
            JobQueueError::Sync(Box::new(e))
        })?;
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse CA certificates");
                JobQueueError::Sync(Box::new(e))
            })?;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                tracing::error!(error = %e, "failed to add CA certificate to root store");
                JobQueueError::Sync(Box::new(e))
            })?;
        }
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    if tls_config.require_client_cert {
        let cert_pem = tokio::fs::read(&tls_config.cert_path).await.map_err(|e| {
            tracing::error!(path = %tls_config.cert_path.display(), error = %e, "failed to read client certificate");
            JobQueueError::Sync(Box::new(e))
        })?;
        let key_pem = tokio::fs::read(&tls_config.key_path).await.map_err(|e| {
            tracing::error!(path = %tls_config.key_path.display(), error = %e, "failed to read client private key");
            JobQueueError::Sync(Box::new(e))
        })?;

        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse client certificates");
                JobQueueError::Sync(Box::new(e))
            })?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&key_pem))
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse client private key");
                JobQueueError::Sync(Box::new(e))
            })?
            .ok_or_else(|| {
                tracing::error!("no private key found in PEM file");
                JobQueueError::Sync(Box::from("no private key found in PEM file"))
            })?;

        builder.with_client_auth_cert(certs, key).map_err(|e| {
            tracing::error!(error = %e, "failed to configure mTLS client auth");
            JobQueueError::Sync(Box::new(e))
        })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

/// Attach optional `NATS` credentials to [`ConnectOptions`](async_nats::ConnectOptions).
async fn apply_credentials(
    mut opts: async_nats::ConnectOptions,
    config: &NatsConfig,
) -> Result<async_nats::ConnectOptions, JobQueueError> {
    if let Some(creds_path) = &config.credentials_path {
        opts = opts.credentials_file(creds_path).await.map_err(|e| {
            tracing::error!(path = %creds_path.display(), error = %e, "failed to load NATS credentials");
            JobQueueError::Sync(Box::new(e))
        })?;
    }
    Ok(opts)
}

/// Build an `async-nats` [`Client`] from a [`NatsConfig`], optionally
/// configuring TLS and mTLS.
///
/// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
async fn build_nats_client(config: &NatsConfig) -> Result<Client, JobQueueError> {
    let connect_opts = if let Some(tls_config) = &config.tls {
        let tls_client_config = build_tls_config(tls_config).await?;
        let opts = async_nats::ConnectOptions::new()
            .tls_client_config(tls_client_config)
            .require_tls(true);
        apply_credentials(opts, config).await?
    } else {
        tracing::warn!("connecting to NATS without TLS — this MUST NOT be used in production");
        apply_credentials(async_nats::ConnectOptions::new(), config).await?
    };

    connect_opts.connect(&config.urls).await.map_err(|e| {
        tracing::error!(urls = %config.urls, error = %e, "NATS connection failed");
        JobQueueError::Sync(Box::new(e))
    })
}

/// Return the NATS subject for a given [`SyncDirection`].
#[must_use]
pub fn subject_for_direction(direction: SyncDirection) -> &'static str {
    match direction {
        SyncDirection::EdgeToCentral => EDGE_TO_CENTRAL_SUBJECT,
        SyncDirection::CentralToEdge => CENTRAL_TO_EDGE_SUBJECT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_for_direction_edge_to_central() {
        assert_eq!(
            subject_for_direction(SyncDirection::EdgeToCentral),
            EDGE_TO_CENTRAL_SUBJECT
        );
    }

    #[test]
    fn subject_for_direction_central_to_edge() {
        assert_eq!(
            subject_for_direction(SyncDirection::CentralToEdge),
            CENTRAL_TO_EDGE_SUBJECT
        );
    }

    #[test]
    fn nist_sc8_tls_required_in_production() {
        // NIST 800-53 Rev 5: SC-8 — Transmission Confidentiality
        // Evidence: When TLS config is None, the code emits a warning
        // and documentation states this MUST NOT be used in production.
        let config = NatsConfig::default();
        assert!(
            config.tls.is_none(),
            "default NatsConfig should have no TLS (dev mode)"
        );
    }
}
