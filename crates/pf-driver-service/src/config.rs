// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for the `IPPS` driver service.
//!
//! Includes listen address, TLS certificate/key paths, maximum job size,
//! and the list of accepted page-description languages (PDLs).

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Default maximum document size: 100 MiB.
const DEFAULT_MAX_JOB_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Default listen address (all interfaces, HTTPS port).
const DEFAULT_LISTEN_ADDR: ([u8; 4], u16) = ([0, 0, 0, 0], 443);

/// Configuration for the `IPPS` driver-service endpoint.
///
/// Loaded from environment variables or a configuration file at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverServiceConfig {
    /// Socket address to bind the `IPPS` listener on.
    pub listen_addr: SocketAddr,

    /// Path to the PEM-encoded server certificate chain.
    pub tls_cert_path: PathBuf,

    /// Path to the PEM-encoded private key.
    pub tls_key_path: PathBuf,

    /// Optional CA bundle for mTLS client-certificate verification.
    pub tls_ca_bundle_path: Option<PathBuf>,

    /// Whether to require a client certificate (mTLS).
    pub require_client_cert: bool,

    /// Maximum accepted document size in bytes.
    pub max_job_size_bytes: u64,

    /// MIME types accepted as document formats (e.g., `application/pdf`).
    pub accepted_document_formats: Vec<String>,
}

impl Default for DriverServiceConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(DEFAULT_LISTEN_ADDR),
            tls_cert_path: PathBuf::from("/etc/printforge/tls/server.crt"),
            tls_key_path: PathBuf::from("/etc/printforge/tls/server.key"),
            tls_ca_bundle_path: None,
            require_client_cert: false,
            max_job_size_bytes: DEFAULT_MAX_JOB_SIZE_BYTES,
            accepted_document_formats: vec![
                "application/pdf".to_string(),
                "image/pwg-raster".to_string(),
                "application/vnd.hp-pcl".to_string(),
            ],
        }
    }
}

impl DriverServiceConfig {
    /// Returns `true` if the given MIME type is in the accepted document formats list.
    #[must_use]
    pub fn is_format_accepted(&self, mime_type: &str) -> bool {
        self.accepted_document_formats
            .iter()
            .any(|fmt| fmt.eq_ignore_ascii_case(mime_type))
    }
}

/// Error type for configuration loading failures.
#[derive(Debug)]
pub struct ConfigError {
    /// The environment variable name that caused the error.
    pub var: String,
    /// Human-readable description of the parse failure.
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid value for {}: {}", self.var, self.message)
    }
}

impl std::error::Error for ConfigError {}

impl DriverServiceConfig {
    /// Constructs a [`DriverServiceConfig`] by reading environment variables
    /// with the `PF_DS_` prefix. Falls back to [`Default`] values for any
    /// variable that is not set.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_DS_LISTEN_ADDR` | `SocketAddr` | Address to bind the IPPS listener |
    /// | `PF_DS_TLS_CERT_PATH` | `PathBuf` | Path to PEM-encoded server certificate |
    /// | `PF_DS_TLS_KEY_PATH` | `PathBuf` | Path to PEM-encoded private key |
    /// | `PF_DS_TLS_CA_BUNDLE_PATH` | `PathBuf` | Optional CA bundle for mTLS |
    /// | `PF_DS_REQUIRE_CLIENT_CERT` | `bool` | Whether to require mTLS |
    /// | `PF_DS_MAX_JOB_SIZE_BYTES` | `u64` | Maximum accepted document size |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        if let Ok(val) = std::env::var("PF_DS_LISTEN_ADDR") {
            cfg.listen_addr = val.parse().map_err(|e| ConfigError {
                var: "PF_DS_LISTEN_ADDR".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_DS_TLS_CERT_PATH") {
            cfg.tls_cert_path = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("PF_DS_TLS_KEY_PATH") {
            cfg.tls_key_path = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("PF_DS_TLS_CA_BUNDLE_PATH") {
            cfg.tls_ca_bundle_path = Some(PathBuf::from(val));
        }

        if let Ok(val) = std::env::var("PF_DS_REQUIRE_CLIENT_CERT") {
            cfg.require_client_cert = val.parse().map_err(|e| ConfigError {
                var: "PF_DS_REQUIRE_CLIENT_CERT".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_DS_MAX_JOB_SIZE_BYTES") {
            cfg.max_job_size_bytes = val.parse().map_err(|e| ConfigError {
                var: "PF_DS_MAX_JOB_SIZE_BYTES".to_string(),
                message: format!("{e}"),
            })?;
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = DriverServiceConfig::default();
        assert_eq!(cfg.listen_addr.port(), 443);
        assert_eq!(cfg.max_job_size_bytes, 100 * 1024 * 1024);
        assert!(!cfg.accepted_document_formats.is_empty());
    }

    #[test]
    fn accepts_pdf_case_insensitive() {
        let cfg = DriverServiceConfig::default();
        assert!(cfg.is_format_accepted("application/pdf"));
        assert!(cfg.is_format_accepted("Application/PDF"));
    }

    #[test]
    fn rejects_unknown_format() {
        let cfg = DriverServiceConfig::default();
        assert!(!cfg.is_format_accepted("application/postscript"));
    }

    #[test]
    fn from_env_returns_defaults_when_no_vars_set() {
        // When none of the PF_DS_* vars are set, from_env falls back to defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let cfg = DriverServiceConfig::from_env().expect("from_env should succeed with defaults");
        let default_cfg = DriverServiceConfig::default();
        assert_eq!(cfg.listen_addr, default_cfg.listen_addr);
        assert_eq!(cfg.tls_cert_path, default_cfg.tls_cert_path);
        assert_eq!(cfg.tls_key_path, default_cfg.tls_key_path);
        assert_eq!(cfg.max_job_size_bytes, default_cfg.max_job_size_bytes);
    }

    #[test]
    fn config_error_displays_var_and_message() {
        let err = ConfigError {
            var: "PF_DS_LISTEN_ADDR".to_string(),
            message: "invalid socket address syntax".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("PF_DS_LISTEN_ADDR"));
        assert!(msg.contains("invalid socket address"));
    }
}
