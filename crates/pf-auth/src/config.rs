// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Authentication configuration.
//!
//! **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment & Management
//!
//! All paths to trust stores, `IdP` endpoints, and TTL settings are configured
//! here. Secrets (signing keys) are wrapped in `secrecy::SecretString`.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

/// Top-level authentication configuration.
///
/// Loaded from `auth.toml` or environment variables at startup.
/// All trust-store paths MUST be absolute and readable by the service account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// OIDC provider settings (Entra ID on NIPR).
    pub oidc: Option<OidcConfig>,

    /// SAML `IdP` settings (DISA E-ICAM on SIPR).
    pub saml: Option<SamlConfig>,

    /// X.509 / CAC/PIV certificate authentication settings.
    pub certificate: CertificateConfig,

    /// JWT issuance settings.
    pub jwt: JwtConfig,

    /// CAC PIN policy.
    pub pin: PinConfig,
}

/// OIDC provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC discovery URL (e.g., `https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration`).
    pub issuer_url: Url,

    /// OAuth 2.0 client ID.
    pub client_id: String,

    /// Redirect URI registered with the `IdP`.
    pub redirect_uri: Url,

    /// Scopes to request (default: `["openid", "profile"]`).
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".to_string(), "profile".to_string()]
}

/// SAML 2.0 Service Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// `IdP` metadata URL or local path.
    pub idp_metadata_url: Url,

    /// SP entity ID.
    pub sp_entity_id: String,

    /// Assertion Consumer Service URL.
    pub acs_url: Url,
}

/// X.509 certificate authentication configuration.
///
/// **NIST 800-53 Rev 5:** IA-5(2), SC-12
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// Path to the PEM bundle of trusted root CAs.
    ///
    /// On NIPR: `DoD` Root CAs. On SIPR: NSS PKI CAs.
    /// If this file is missing or empty, all cert auth MUST fail (fail-closed).
    pub trust_store_path: PathBuf,

    /// Whether to check revocation via OCSP.
    #[serde(default = "default_true")]
    pub ocsp_enabled: bool,

    /// OCSP response cache TTL. Default: 4 hours.
    #[serde(
        default = "default_ocsp_ttl",
        with = "humantime_serde",
        rename = "ocsp_cache_ttl"
    )]
    pub ocsp_cache_ttl: Duration,

    /// Maximum number of cached OCSP responses (LRU eviction).
    #[serde(default = "default_ocsp_cache_size")]
    pub ocsp_cache_size: usize,

    /// Whether to fall back to CRL if OCSP is unavailable.
    #[serde(default = "default_true")]
    pub crl_fallback_enabled: bool,

    /// Directory to cache downloaded CRLs.
    pub crl_cache_dir: Option<PathBuf>,

    /// CRL refresh interval. Default: 24 hours.
    #[serde(default = "default_crl_refresh", with = "humantime_serde")]
    pub crl_refresh_interval: Duration,
}

fn default_true() -> bool {
    true
}

fn default_ocsp_ttl() -> Duration {
    Duration::from_secs(4 * 60 * 60) // 4 hours
}

fn default_ocsp_cache_size() -> usize {
    10_000
}

fn default_crl_refresh() -> Duration {
    Duration::from_secs(24 * 60 * 60) // 24 hours
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            trust_store_path: PathBuf::from("/etc/printforge/trust-store.pem"),
            ocsp_enabled: true,
            ocsp_cache_ttl: default_ocsp_ttl(),
            ocsp_cache_size: default_ocsp_cache_size(),
            crl_fallback_enabled: true,
            crl_cache_dir: None,
            crl_refresh_interval: default_crl_refresh(),
        }
    }
}

/// JWT issuance configuration.
///
/// **NIST 800-53 Rev 5:** SC-12, IA-5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Issuer claim (`iss`).
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,

    /// Audience claim (`aud`).
    #[serde(default = "default_jwt_audience")]
    pub audience: String,

    /// Access token lifetime for web sessions.
    #[serde(default = "default_session_ttl", with = "humantime_serde")]
    pub session_ttl: Duration,

    /// Access token lifetime for printer-scoped tokens.
    #[serde(default = "default_printer_ttl", with = "humantime_serde")]
    pub printer_ttl: Duration,
}

fn default_jwt_issuer() -> String {
    "printforge".to_string()
}

fn default_jwt_audience() -> String {
    "printforge-api".to_string()
}

fn default_session_ttl() -> Duration {
    Duration::from_secs(60 * 60) // 1 hour
}

fn default_printer_ttl() -> Duration {
    Duration::from_secs(15 * 60) // 15 minutes
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
            session_ttl: default_session_ttl(),
            printer_ttl: default_printer_ttl(),
        }
    }
}

/// CAC PIN policy configuration.
///
/// **NIST 800-53 Rev 5:** AC-7 — Unsuccessful Logon Attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinConfig {
    /// Maximum consecutive failed PIN attempts before lockout.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Lockout duration after exceeding `max_attempts`.
    #[serde(default = "default_lockout_duration", with = "humantime_serde")]
    pub lockout_duration: Duration,
}

fn default_max_attempts() -> u32 {
    3
}

fn default_lockout_duration() -> Duration {
    Duration::from_secs(30 * 60) // 30 minutes
}

impl Default for PinConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            lockout_duration: default_lockout_duration(),
        }
    }
}

/// Serde support for `Duration` as human-readable strings (e.g., "4h", "30m").
mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid duration: {s}")))
    }

    fn parse_duration(s: &str) -> Option<Duration> {
        let s = s.trim();
        if let Some(rest) = s.strip_suffix('s') {
            rest.trim().parse::<u64>().ok().map(Duration::from_secs)
        } else if let Some(rest) = s.strip_suffix('m') {
            rest.trim()
                .parse::<u64>()
                .ok()
                .map(|m| Duration::from_secs(m * 60))
        } else if let Some(rest) = s.strip_suffix('h') {
            rest.trim()
                .parse::<u64>()
                .ok()
                .map(|h| Duration::from_secs(h * 3600))
        } else {
            s.parse::<u64>().ok().map(Duration::from_secs)
        }
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

impl AuthConfig {
    /// Constructs an [`AuthConfig`] by reading environment variables with
    /// the `PF_AUTH_` prefix. Falls back to [`Default`] values for sub-configs
    /// when variables are not set.
    ///
    /// This method builds the `certificate`, `jwt`, and `pin` sub-configs
    /// from environment variables; OIDC and SAML remain `None` (those
    /// require full file-based config due to URL complexity).
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_AUTH_TRUST_STORE_PATH` | `PathBuf` | PEM bundle of trusted root CAs |
    /// | `PF_AUTH_OCSP_CACHE_TTL_SECS` | `u64` | OCSP response cache TTL in seconds |
    /// | `PF_AUTH_OCSP_CACHE_SIZE` | `usize` | Maximum OCSP cache entries |
    /// | `PF_AUTH_JWT_ISSUER` | `String` | JWT `iss` claim |
    /// | `PF_AUTH_JWT_AUDIENCE` | `String` | JWT `aud` claim |
    /// | `PF_AUTH_SESSION_TTL_SECS` | `u64` | Web session token lifetime in seconds |
    /// | `PF_AUTH_PRINTER_TTL_SECS` | `u64` | Printer-scoped token lifetime in seconds |
    /// | `PF_AUTH_PIN_MAX_ATTEMPTS` | `u32` | Max consecutive failed PIN attempts |
    /// | `PF_AUTH_PIN_LOCKOUT_SECS` | `u64` | Lockout duration after max PIN failures |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cert_cfg = CertificateConfig::default();
        let mut jwt_cfg = JwtConfig::default();
        let mut pin_cfg = PinConfig::default();

        // Certificate config overrides.
        if let Ok(val) = std::env::var("PF_AUTH_TRUST_STORE_PATH") {
            cert_cfg.trust_store_path = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("PF_AUTH_OCSP_CACHE_TTL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_AUTH_OCSP_CACHE_TTL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            cert_cfg.ocsp_cache_ttl = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_AUTH_OCSP_CACHE_SIZE") {
            cert_cfg.ocsp_cache_size = val.parse().map_err(|e| ConfigError {
                var: "PF_AUTH_OCSP_CACHE_SIZE".to_string(),
                message: format!("{e}"),
            })?;
        }

        // JWT config overrides.
        if let Ok(val) = std::env::var("PF_AUTH_JWT_ISSUER") {
            jwt_cfg.issuer = val;
        }

        if let Ok(val) = std::env::var("PF_AUTH_JWT_AUDIENCE") {
            jwt_cfg.audience = val;
        }

        if let Ok(val) = std::env::var("PF_AUTH_SESSION_TTL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_AUTH_SESSION_TTL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            jwt_cfg.session_ttl = Duration::from_secs(secs);
        }

        if let Ok(val) = std::env::var("PF_AUTH_PRINTER_TTL_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_AUTH_PRINTER_TTL_SECS".to_string(),
                message: format!("{e}"),
            })?;
            jwt_cfg.printer_ttl = Duration::from_secs(secs);
        }

        // PIN config overrides.
        if let Ok(val) = std::env::var("PF_AUTH_PIN_MAX_ATTEMPTS") {
            pin_cfg.max_attempts = val.parse().map_err(|e| ConfigError {
                var: "PF_AUTH_PIN_MAX_ATTEMPTS".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_AUTH_PIN_LOCKOUT_SECS") {
            let secs: u64 = val.parse().map_err(|e| ConfigError {
                var: "PF_AUTH_PIN_LOCKOUT_SECS".to_string(),
                message: format!("{e}"),
            })?;
            pin_cfg.lockout_duration = Duration::from_secs(secs);
        }

        Ok(Self {
            oidc: None,
            saml: None,
            certificate: cert_cfg,
            jwt: jwt_cfg,
            pin: pin_cfg,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_certificate_config_has_sane_defaults() {
        let cfg = CertificateConfig::default();
        assert!(cfg.ocsp_enabled);
        assert!(cfg.crl_fallback_enabled);
        assert_eq!(cfg.ocsp_cache_ttl, Duration::from_secs(4 * 3600));
        assert_eq!(cfg.ocsp_cache_size, 10_000);
    }

    #[test]
    fn default_jwt_config_has_short_lifetimes() {
        let cfg = JwtConfig::default();
        assert_eq!(cfg.session_ttl, Duration::from_secs(3600));
        assert_eq!(cfg.printer_ttl, Duration::from_secs(900));
    }

    #[test]
    fn nist_ac7_default_pin_config() {
        let cfg = PinConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.lockout_duration, Duration::from_secs(30 * 60));
    }

    #[test]
    fn from_env_returns_defaults_when_no_vars_set() {
        // When none of the PF_AUTH_* vars are set, from_env falls back to defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let cfg = AuthConfig::from_env().expect("from_env should succeed with defaults");
        let default_cert = CertificateConfig::default();
        let default_jwt = JwtConfig::default();
        let default_pin = PinConfig::default();

        assert!(cfg.oidc.is_none());
        assert!(cfg.saml.is_none());
        assert_eq!(cfg.certificate.trust_store_path, default_cert.trust_store_path);
        assert_eq!(cfg.certificate.ocsp_cache_ttl, default_cert.ocsp_cache_ttl);
        assert_eq!(cfg.jwt.issuer, default_jwt.issuer);
        assert_eq!(cfg.jwt.audience, default_jwt.audience);
        assert_eq!(cfg.pin.max_attempts, default_pin.max_attempts);
    }

    #[test]
    fn config_error_displays_var_and_message() {
        let err = ConfigError {
            var: "PF_AUTH_OCSP_CACHE_TTL_SECS".to_string(),
            message: "invalid digit found in string".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("PF_AUTH_OCSP_CACHE_TTL_SECS"));
        assert!(msg.contains("invalid digit"));
    }
}
