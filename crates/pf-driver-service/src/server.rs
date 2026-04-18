// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `IPPS` server types: TLS listener configuration and connection handling.
//!
//! This module defines the server context and connection-handler types for
//! the `IPPS` endpoint. All connections MUST be TLS — plaintext `IPP` is
//! never accepted.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality

use std::net::SocketAddr;

use crate::config::DriverServiceConfig;
use crate::error::DriverServiceError;
use crate::tls::TlsSettings;

/// State shared across all connections to the `IPPS` server.
///
/// Holds the resolved configuration and TLS settings needed to accept
/// and process incoming print-job submissions.
#[derive(Debug, Clone)]
pub struct ServerContext {
    /// Resolved service configuration.
    pub config: DriverServiceConfig,
    /// Validated TLS settings.
    pub tls_settings: TlsSettings,
}

impl ServerContext {
    /// Create a new `ServerContext` from the given configuration.
    ///
    /// Validates TLS settings at construction time so that startup fails
    /// early if certificates are missing.
    ///
    /// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
    ///
    /// # Errors
    ///
    /// Returns `DriverServiceError::Tls` if TLS certificate or key
    /// validation fails.
    pub fn new(config: DriverServiceConfig) -> Result<Self, DriverServiceError> {
        let tls_settings = TlsSettings::from_config(&config)?;
        Ok(Self {
            config,
            tls_settings,
        })
    }

    /// Return the socket address this server should bind to.
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }
}

/// Outcome of processing a single `IPPS` connection.
#[derive(Debug)]
pub enum ConnectionOutcome {
    /// The connection was handled successfully (one or more operations served).
    Success {
        /// Number of `IPP` operations served on this connection.
        operations_served: u32,
    },
    /// The TLS handshake failed — connection dropped.
    ///
    /// **NIST 800-53 Rev 5:** SC-8
    TlsHandshakeFailed {
        /// Peer address, if available.
        peer_addr: Option<SocketAddr>,
        /// Reason the handshake failed.
        reason: String,
    },
    /// A plaintext (non-TLS) connection was attempted and rejected.
    ///
    /// **NIST 800-53 Rev 5:** SC-8
    PlaintextRejected {
        /// Peer address.
        peer_addr: Option<SocketAddr>,
    },
    /// The client sent an invalid or malformed `IPP` message.
    MalformedRequest {
        /// Description of the parsing failure.
        reason: String,
    },
}

/// Metadata about an active `IPPS` connection for logging and audit.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Whether the client presented a certificate (mTLS).
    pub client_cert_presented: bool,
    /// The Common Name from the client certificate, if mTLS was used.
    pub client_cert_cn: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn server_context_rejects_missing_tls() {
        let config = DriverServiceConfig {
            tls_cert_path: "/nonexistent/cert.pem".into(),
            tls_key_path: "/nonexistent/key.pem".into(),
            ..DriverServiceConfig::default()
        };
        assert!(ServerContext::new(config).is_err());
    }

    #[test]
    fn connection_info_fields() {
        let info = ConnectionInfo {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            client_cert_presented: false,
            client_cert_cn: None,
        };
        assert_eq!(info.peer_addr.port(), 12345);
        assert!(!info.client_cert_presented);
    }

    #[test]
    fn nist_sc8_plaintext_rejected_outcome() {
        let outcome = ConnectionOutcome::PlaintextRejected {
            peer_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 631)),
        };
        assert!(matches!(
            outcome,
            ConnectionOutcome::PlaintextRejected { .. }
        ));
    }
}
