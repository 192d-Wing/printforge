// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Gateway configuration: listen address, TLS, rate limits, CORS origins.
//!
//! **NIST 800-53 Rev 5:** AC-17 — Remote Access, SC-8 — Transmission Confidentiality

use std::net::SocketAddr;

use pf_common::config::TlsConfig;
use serde::{Deserialize, Serialize};

/// JWT validation configuration.
///
/// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtValidationConfig {
    /// Expected issuer (`iss` claim).
    pub issuer: String,
    /// Expected audience (`aud` claim).
    pub audience: String,
    /// PEM-encoded Ed25519 public key for signature verification.
    pub public_key_pem: String,
}

impl Default for JwtValidationConfig {
    fn default() -> Self {
        Self {
            issuer: "printforge".to_string(),
            audience: "printforge-api".to_string(),
            public_key_pem: String::new(),
        }
    }
}

/// Top-level configuration for the API gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Socket address to bind the HTTPS listener.
    pub listen_addr: SocketAddr,
    /// TLS configuration. Required in production — the gateway MUST NOT
    /// serve plaintext HTTP.
    ///
    /// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
    pub tls: Option<TlsConfig>,
    /// JWT validation configuration.
    ///
    /// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
    pub jwt: JwtValidationConfig,
    /// Rate-limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// CORS configuration.
    pub cors: CorsConfig,
    /// Maximum request body size in bytes (default: 1 MiB for non-upload routes).
    pub max_body_size: usize,
    /// Maximum request body size for job upload routes (default: 50 MiB).
    pub max_upload_size: usize,
    /// Graceful shutdown timeout in seconds.
    pub shutdown_timeout_secs: u64,
    /// Background job configuration (retention sweeps, report worker).
    pub background: BackgroundConfig,
}

/// Configuration for background cron-like tasks spawned at server startup.
///
/// Tasks are only spawned when the corresponding service handle is wired
/// into [`AppState`](crate::AppState); e.g., the alert retention sweep only
/// runs if [`AppState::alert_service`] is `Some`.
///
/// **NIST 800-53 Rev 5:** AU-11 — Audit Record Retention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundConfig {
    /// Whether background tasks run at all. Set to `false` for short-lived
    /// one-shot deployments (migrations, smoke tests).
    pub enabled: bool,
    /// How often the alert retention sweep runs, in seconds.
    pub alert_sweep_interval_secs: u64,
    /// How long Resolved alerts are retained, in days. Alerts older than
    /// this are deleted by the retention sweep. Active and Acknowledged
    /// alerts are never swept.
    pub alert_retention_days: i64,
    /// How often the report worker polls for Pending rows, in seconds.
    pub report_poll_interval_secs: u64,
}

impl Default for BackgroundConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // 1 hour: sweeps rarely vs. alert churn. Can tighten in prod.
            alert_sweep_interval_secs: 3600,
            // 30 days: long enough for post-incident review, short enough
            // to keep the table compact.
            alert_retention_days: 30,
            // 5 seconds: low latency from enqueue to worker pickup without
            // hammering the DB.
            report_poll_interval_secs: 5,
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            tls: None,
            jwt: JwtValidationConfig::default(),
            rate_limit: RateLimitConfig::default(),
            cors: CorsConfig::default(),
            max_body_size: 1_048_576,    // 1 MiB
            max_upload_size: 52_428_800, // 50 MiB
            shutdown_timeout_secs: 30,
            background: BackgroundConfig::default(),
        }
    }
}

/// Token-bucket rate limiting configuration.
///
/// Applies per-IP and per-user limits independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    pub enabled: bool,
    /// Maximum requests per second per client IP address.
    pub per_ip_rps: u32,
    /// Burst capacity for the per-IP bucket.
    pub per_ip_burst: u32,
    /// Maximum requests per second per authenticated user.
    pub per_user_rps: u32,
    /// Burst capacity for the per-user bucket.
    pub per_user_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_rps: 100,
            per_ip_burst: 200,
            per_user_rps: 50,
            per_user_burst: 100,
        }
    }
}

/// CORS configuration for the API gateway.
///
/// **NIST 800-53 Rev 5:** SC-8 — no wildcard origins allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins. Must not contain `*`.
    pub allowed_origins: Vec<String>,
    /// Maximum age (seconds) for preflight cache.
    pub max_age_secs: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            max_age_secs: 3600,
        }
    }
}

impl GatewayConfig {
    /// Load configuration from environment variables, falling back to defaults.
    ///
    /// | Variable | Field | Example |
    /// |---|---|---|
    /// | `PF_GW_LISTEN_ADDR` | `listen_addr` | `0.0.0.0:8443` |
    /// | `PF_GW_JWT_ISSUER` | `jwt.issuer` | `printforge` |
    /// | `PF_GW_JWT_AUDIENCE` | `jwt.audience` | `printforge-api` |
    /// | `PF_GW_JWT_PUBLIC_KEY_PEM` | `jwt.public_key_pem` | PEM string |
    /// | `PF_GW_RATE_LIMIT_ENABLED` | `rate_limit.enabled` | `true` |
    /// | `PF_GW_MAX_BODY_SIZE` | `max_body_size` | `1048576` |
    /// | `PF_GW_MAX_UPLOAD_SIZE` | `max_upload_size` | `52428800` |
    /// | `PF_GW_SHUTDOWN_TIMEOUT` | `shutdown_timeout_secs` | `30` |
    ///
    /// # Errors
    ///
    /// Returns an error if an environment variable is present but contains an
    /// unparseable value.
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let mut cfg = Self::default();

        if let Ok(v) = std::env::var("PF_GW_LISTEN_ADDR") {
            cfg.listen_addr = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_LISTEN_ADDR '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_JWT_ISSUER") {
            cfg.jwt.issuer = v;
        }

        if let Ok(v) = std::env::var("PF_GW_JWT_AUDIENCE") {
            cfg.jwt.audience = v;
        }

        if let Ok(v) = std::env::var("PF_GW_JWT_PUBLIC_KEY_PEM") {
            cfg.jwt.public_key_pem = v;
        }

        if let Ok(v) = std::env::var("PF_GW_RATE_LIMIT_ENABLED") {
            cfg.rate_limit.enabled = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_RATE_LIMIT_ENABLED '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_MAX_BODY_SIZE") {
            cfg.max_body_size = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_MAX_BODY_SIZE '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_MAX_UPLOAD_SIZE") {
            cfg.max_upload_size = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_MAX_UPLOAD_SIZE '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_SHUTDOWN_TIMEOUT") {
            cfg.shutdown_timeout_secs = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_SHUTDOWN_TIMEOUT '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_BACKGROUND_ENABLED") {
            cfg.background.enabled = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_BACKGROUND_ENABLED '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_ALERT_SWEEP_INTERVAL") {
            cfg.background.alert_sweep_interval_secs = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_ALERT_SWEEP_INTERVAL '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_ALERT_RETENTION_DAYS") {
            cfg.background.alert_retention_days = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_ALERT_RETENTION_DAYS '{v}': {e}")
            })?;
        }

        if let Ok(v) = std::env::var("PF_GW_REPORT_POLL_INTERVAL") {
            cfg.background.report_poll_interval_secs = v.parse().map_err(|e| {
                anyhow::anyhow!("invalid PF_GW_REPORT_POLL_INTERVAL '{v}': {e}")
            })?;
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_binds_to_8443() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.listen_addr.port(), 8443);
    }

    #[test]
    fn default_body_limits() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.max_body_size, 1_048_576);
        assert_eq!(cfg.max_upload_size, 52_428_800);
    }

    #[test]
    fn nist_sc8_default_cors_has_no_wildcard() {
        // NIST 800-53 Rev 5: SC-8 — Transmission Confidentiality
        // Evidence: Default CORS config does not allow any origin (no wildcard).
        let cfg = CorsConfig::default();
        assert!(cfg.allowed_origins.is_empty());
        assert!(!cfg.allowed_origins.contains(&"*".to_string()));
    }

    #[test]
    fn config_serializes_round_trip() {
        let cfg = GatewayConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: GatewayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.listen_addr, cfg.listen_addr);
        assert_eq!(parsed.max_body_size, cfg.max_body_size);
    }

    #[test]
    fn rate_limit_defaults_are_reasonable() {
        let cfg = RateLimitConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.per_ip_rps > 0);
        assert!(cfg.per_ip_burst >= cfg.per_ip_rps);
    }
}
