// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Real `async-nats` client for the cache node's leaf connection to the
//! central `NATS` cluster.
//!
//! Provides publish/subscribe primitives and connection-state awareness
//! used by the heartbeat, job sync, and audit subsystems.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
//! All `NATS` connections use TLS with mTLS in production.
//!
//! **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
//! Disconnection detection drives `DDIL` mode transitions.

use async_nats::Client;
use bytes::Bytes;
use pf_common::config::NatsConfig;

use crate::error::CacheNodeError;

/// `NATS` subject prefix for heartbeat messages.
pub const HEARTBEAT_SUBJECT: &str = "printforge.cache.heartbeat";
/// `NATS` subject prefix for audit event forwarding.
pub const AUDIT_SUBJECT: &str = "printforge.audit.events";
/// `NATS` subject prefix for job sync messages.
pub const JOB_SYNC_SUBJECT: &str = "printforge.jobs.sync";

/// A `NATS` client for the cache node that wraps `async-nats` with
/// connection-state awareness and message publishing/subscribing.
///
/// The `async-nats` library handles automatic reconnection internally.
/// This wrapper exposes a [`is_connected`](Self::is_connected) method
/// that the orchestrator uses to drive `DDIL` mode transitions.
#[derive(Debug, Clone)]
pub struct NatsClient {
    /// The underlying `async-nats` [`Client`].
    client: Client,
    /// Site identifier included in published messages for routing.
    site_id: String,
}

/// A subscription handle that yields messages from a `NATS` subject.
#[derive(Debug)]
pub struct NatsSubscription {
    /// The underlying `async-nats` subscriber.
    inner: async_nats::Subscriber,
    /// The subject this subscription is listening on.
    subject: String,
}

impl NatsClient {
    /// Connect to the central `NATS` cluster as a leaf node.
    ///
    /// When `NatsConfig::tls` is `Some`, TLS (and optionally mTLS) is
    /// configured. The `async-nats` client handles reconnection
    /// automatically; callers should poll [`is_connected`](Self::is_connected)
    /// to detect connectivity loss for `DDIL` transitions.
    ///
    /// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` if the connection cannot be established.
    pub async fn connect(config: &NatsConfig, site_id: &str) -> Result<Self, CacheNodeError> {
        let client = build_nats_client(config).await?;

        tracing::info!(
            urls = %config.urls,
            %site_id,
            tls_enabled = config.tls.is_some(),
            "cache node NATS client connected"
        );

        Ok(Self {
            client,
            site_id: site_id.to_owned(),
        })
    }

    /// Publish a message to the given `NATS` subject.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` on publish failure.
    pub async fn publish(&self, subject: &str, payload: &[u8]) -> Result<(), CacheNodeError> {
        self.client
            .publish(subject.to_owned(), Bytes::from(payload.to_vec()))
            .await
            .map_err(|e| {
                tracing::error!(%subject, error = %e, "NATS publish failed");
                CacheNodeError::Nats {
                    message: format!("publish to {subject} failed: {e}"),
                }
            })?;

        tracing::debug!(%subject, bytes = payload.len(), "published NATS message");
        Ok(())
    }

    /// Publish a heartbeat message to the central cluster.
    ///
    /// The heartbeat payload is a JSON object identifying this site.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` on publish failure.
    pub async fn publish_heartbeat(&self, payload: &[u8]) -> Result<(), CacheNodeError> {
        let subject = format!("{HEARTBEAT_SUBJECT}.{}", self.site_id);
        self.publish(&subject, payload).await
    }

    /// Publish an audit event to the central cluster.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` on publish failure.
    pub async fn publish_audit_event(&self, payload: &[u8]) -> Result<(), CacheNodeError> {
        let subject = format!("{AUDIT_SUBJECT}.{}", self.site_id);
        self.publish(&subject, payload).await
    }

    /// Publish a job sync message.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` on publish failure.
    pub async fn publish_job_sync(&self, payload: &[u8]) -> Result<(), CacheNodeError> {
        let subject = format!("{JOB_SYNC_SUBJECT}.{}", self.site_id);
        self.publish(&subject, payload).await
    }

    /// Subscribe to a `NATS` subject and return a [`NatsSubscription`]
    /// that yields incoming messages.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` if the subscription fails.
    pub async fn subscribe(&self, subject: &str) -> Result<NatsSubscription, CacheNodeError> {
        let subscriber = self
            .client
            .subscribe(subject.to_owned())
            .await
            .map_err(|e| {
                tracing::error!(%subject, error = %e, "NATS subscribe failed");
                CacheNodeError::Nats {
                    message: format!("subscribe to {subject} failed: {e}"),
                }
            })?;

        tracing::info!(%subject, "subscribed to NATS subject");

        Ok(NatsSubscription {
            inner: subscriber,
            subject: subject.to_owned(),
        })
    }

    /// Check whether the `NATS` client is currently connected.
    ///
    /// This is used by the heartbeat/orchestrator to detect connectivity
    /// loss and trigger `DDIL` mode transitions.
    ///
    /// **NIST 800-53 Rev 5:** CP-7 — Alternate Processing Site
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.client.connection_state() == async_nats::connection::State::Connected
    }

    /// Return a reference to the underlying `async-nats` [`Client`].
    #[must_use]
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Return the site identifier for this cache node.
    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site_id
    }
}

impl NatsSubscription {
    /// Receive the next message from this subscription.
    ///
    /// Returns `Ok(None)` if the subscription has been closed.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` on deserialization failure of the
    /// wrapper (the raw payload is returned as bytes for the caller to
    /// deserialize).
    pub async fn next_message(&mut self) -> Option<NatsMessage> {
        use futures_util::StreamExt as _;
        let msg = self.inner.next().await?;

        Some(NatsMessage {
            subject: msg.subject.to_string(),
            payload: msg.payload.to_vec(),
        })
    }

    /// Return the subject this subscription is listening on.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// A received `NATS` message with subject and payload.
#[derive(Debug, Clone)]
pub struct NatsMessage {
    /// The `NATS` subject the message was received on.
    pub subject: String,
    /// The raw message payload.
    pub payload: Vec<u8>,
}

/// Build a `rustls` [`ClientConfig`](rustls::ClientConfig) from the
/// provided [`TlsConfig`](pf_common::config::TlsConfig), loading CA
/// trust anchors and optional client certificates for mTLS.
///
/// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
async fn build_tls_config(
    tls_config: &pf_common::config::TlsConfig,
) -> Result<rustls::ClientConfig, CacheNodeError> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &tls_config.ca_bundle_path {
        let ca_pem = tokio::fs::read(ca_path).await.map_err(|e| {
            tracing::error!(path = %ca_path.display(), error = %e, "failed to read CA bundle");
            CacheNodeError::Nats {
                message: format!("failed to read CA bundle: {e}"),
            }
        })?;
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse CA certificates");
                CacheNodeError::Nats {
                    message: format!("failed to parse CA certificates: {e}"),
                }
            })?;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                tracing::error!(error = %e, "failed to add CA certificate");
                CacheNodeError::Nats {
                    message: format!("failed to add CA certificate: {e}"),
                }
            })?;
        }
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    if tls_config.require_client_cert {
        let cert_pem = tokio::fs::read(&tls_config.cert_path).await.map_err(|e| {
            tracing::error!(path = %tls_config.cert_path.display(), error = %e, "failed to read client certificate");
            CacheNodeError::Nats {
                message: format!("failed to read client cert: {e}"),
            }
        })?;
        let key_pem = tokio::fs::read(&tls_config.key_path).await.map_err(|e| {
            tracing::error!(path = %tls_config.key_path.display(), error = %e, "failed to read client private key");
            CacheNodeError::Nats {
                message: format!("failed to read client key: {e}"),
            }
        })?;

        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse client certificates");
                CacheNodeError::Nats {
                    message: format!("failed to parse client certs: {e}"),
                }
            })?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&key_pem))
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse client private key");
                CacheNodeError::Nats {
                    message: format!("failed to parse client key: {e}"),
                }
            })?
            .ok_or_else(|| {
                tracing::error!("no private key found in PEM file");
                CacheNodeError::Nats {
                    message: "no private key found in PEM file".to_owned(),
                }
            })?;

        builder.with_client_auth_cert(certs, key).map_err(|e| {
            tracing::error!(error = %e, "failed to configure mTLS client auth");
            CacheNodeError::Nats {
                message: format!("mTLS client auth config failed: {e}"),
            }
        })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

/// Attach optional `NATS` credentials to [`ConnectOptions`](async_nats::ConnectOptions).
async fn apply_credentials(
    mut opts: async_nats::ConnectOptions,
    config: &NatsConfig,
) -> Result<async_nats::ConnectOptions, CacheNodeError> {
    if let Some(creds_path) = &config.credentials_path {
        opts = opts.credentials_file(creds_path).await.map_err(|e| {
            tracing::error!(path = %creds_path.display(), error = %e, "failed to load NATS credentials");
            CacheNodeError::Nats {
                message: format!("failed to load credentials: {e}"),
            }
        })?;
    }
    Ok(opts)
}

/// Build an `async-nats` [`Client`] from a [`NatsConfig`], optionally
/// configuring TLS and mTLS.
///
/// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
async fn build_nats_client(config: &NatsConfig) -> Result<Client, CacheNodeError> {
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
        CacheNodeError::Nats {
            message: format!("NATS connection failed: {e}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_subject_includes_site_id() {
        let subject = format!("{HEARTBEAT_SUBJECT}.site-alpha");
        assert_eq!(subject, "printforge.cache.heartbeat.site-alpha");
    }

    #[test]
    fn audit_subject_includes_site_id() {
        let subject = format!("{AUDIT_SUBJECT}.site-beta");
        assert_eq!(subject, "printforge.audit.events.site-beta");
    }

    #[test]
    fn job_sync_subject_includes_site_id() {
        let subject = format!("{JOB_SYNC_SUBJECT}.site-gamma");
        assert_eq!(subject, "printforge.jobs.sync.site-gamma");
    }

    #[test]
    fn nats_message_clone() {
        let msg = NatsMessage {
            subject: "test.subject".to_owned(),
            payload: vec![1, 2, 3],
        };
        let cloned = msg.clone();
        assert_eq!(cloned.subject, "test.subject");
        assert_eq!(cloned.payload, vec![1, 2, 3]);
    }

    #[test]
    fn nist_sc8_tls_config_default_is_none() {
        // NIST 800-53 Rev 5: SC-8 — Transmission Confidentiality
        // Evidence: Default NatsConfig has no TLS (dev only). Production
        // deployments MUST supply a TlsConfig with mTLS enabled.
        let config = NatsConfig::default();
        assert!(config.tls.is_none());
    }
}
