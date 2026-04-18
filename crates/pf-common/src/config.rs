// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Shared configuration types used across multiple crates.

use std::env;
use std::path::PathBuf;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::CommonError;

/// TLS configuration for any service that terminates or initiates TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key.
    pub key_path: PathBuf,
    /// Path to the CA bundle for client/server verification.
    pub ca_bundle_path: Option<PathBuf>,
    /// Whether to require mTLS (client certificate).
    pub require_client_cert: bool,
}

/// Database connection configuration (`PostgreSQL`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    /// Password is wrapped in `SecretString` to prevent accidental logging.
    #[serde(skip)]
    pub password: Option<SecretString>,
    /// Maximum connections in the pool.
    pub max_connections: u32,
    /// Optional TLS config for the database connection.
    pub tls: Option<TlsConfig>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            database: "printforge".to_string(),
            username: "printforge".to_string(),
            password: None,
            max_connections: 10,
            tls: None,
        }
    }
}

impl DatabaseConfig {
    /// Constructs a [`DatabaseConfig`] from environment variables.
    ///
    /// | Variable | Required | Default |
    /// |---|---|---|
    /// | `PF_DB_HOST` | no | `localhost` |
    /// | `PF_DB_PORT` | no | `5432` |
    /// | `PF_DB_NAME` | no | `printforge` |
    /// | `PF_DB_USER` | no | `printforge` |
    /// | `PF_DB_PASSWORD` | no | *(none)* |
    /// | `PF_DB_MAX_CONNECTIONS` | no | `10` |
    ///
    /// Calls [`dotenvy::dotenv`] first so `.env` files are loaded automatically.
    pub fn from_env() -> Result<Self, CommonError> {
        dotenvy::dotenv().ok();

        let host = env::var("PF_DB_HOST").unwrap_or_else(|_| "localhost".to_string());

        let port: u16 = env::var("PF_DB_PORT")
            .unwrap_or_else(|_| "5432".to_string())
            .parse()
            .map_err(|e| CommonError::Config {
                message: format!("invalid PF_DB_PORT: {e}"),
            })?;

        let database = env::var("PF_DB_NAME").unwrap_or_else(|_| "printforge".to_string());
        let username = env::var("PF_DB_USER").unwrap_or_else(|_| "printforge".to_string());

        let password = env::var("PF_DB_PASSWORD")
            .ok()
            .map(SecretString::from);

        let max_connections: u32 = env::var("PF_DB_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .map_err(|e| CommonError::Config {
                message: format!("invalid PF_DB_MAX_CONNECTIONS: {e}"),
            })?;

        Ok(Self {
            host,
            port,
            database,
            username,
            password,
            max_connections,
            tls: None,
        })
    }
}

/// NATS messaging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// NATS server URL(s), comma-separated for cluster.
    pub urls: String,
    /// Optional TLS config for the NATS connection.
    pub tls: Option<TlsConfig>,
    /// Optional credentials file path for NATS authentication.
    pub credentials_path: Option<PathBuf>,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            urls: "nats://localhost:4222".to_string(),
            tls: None,
            credentials_path: None,
        }
    }
}

impl NatsConfig {
    /// Constructs a [`NatsConfig`] from environment variables.
    ///
    /// | Variable | Required | Default |
    /// |---|---|---|
    /// | `PF_NATS_URL` | no | `nats://localhost:4222` |
    ///
    /// Calls [`dotenvy::dotenv`] first so `.env` files are loaded automatically.
    pub fn from_env() -> Result<Self, CommonError> {
        dotenvy::dotenv().ok();

        let urls = env::var("PF_NATS_URL")
            .unwrap_or_else(|_| "nats://localhost:4222".to_string());

        Ok(Self {
            urls,
            tls: None,
            credentials_path: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_config_default_works() {
        let cfg = DatabaseConfig::default();
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 5432);
        assert_eq!(cfg.database, "printforge");
        assert_eq!(cfg.username, "printforge");
        assert!(cfg.password.is_none());
        assert_eq!(cfg.max_connections, 10);
    }

    #[test]
    fn nats_config_default_works() {
        let cfg = NatsConfig::default();
        assert_eq!(cfg.urls, "nats://localhost:4222");
    }

    #[test]
    fn database_config_from_env_uses_defaults_when_vars_unset() {
        // When none of the PF_DB_* vars are set, from_env falls back to defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let cfg = DatabaseConfig::from_env().expect("from_env should succeed with defaults");
        // Defaults match DatabaseConfig::default() for host, port, database, username.
        assert_eq!(cfg.host, DatabaseConfig::default().host);
        assert_eq!(cfg.port, DatabaseConfig::default().port);
        assert_eq!(cfg.database, DatabaseConfig::default().database);
        assert_eq!(cfg.username, DatabaseConfig::default().username);
        assert_eq!(cfg.max_connections, DatabaseConfig::default().max_connections);
    }

    #[test]
    fn nats_config_from_env_uses_defaults_when_vars_unset() {
        let cfg = NatsConfig::from_env().expect("from_env should succeed with defaults");
        assert_eq!(cfg.urls, NatsConfig::default().urls);
    }

    #[test]
    fn password_not_leaked_in_debug_output() {
        // Construct a DatabaseConfig with a known password directly.
        let cfg = DatabaseConfig {
            password: Some(SecretString::from("super-secret-password-12345".to_string())),
            ..DatabaseConfig::default()
        };
        let debug_str = format!("{cfg:?}");

        // The password value must NOT appear in Debug output.
        assert!(
            !debug_str.contains("super-secret-password-12345"),
            "password was leaked in Debug output: {debug_str}"
        );
    }
}
