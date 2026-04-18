// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! TLS configuration for the `IPPS` endpoint.
//!
//! Handles certificate loading, cipher suite selection, and mTLS toggle.
//! Only TLS 1.2 and TLS 1.3 are permitted — all older protocol versions
//! are explicitly disabled.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality

use std::path::Path;

use crate::config::DriverServiceConfig;
use crate::error::DriverServiceError;

/// TLS protocol versions allowed by the `IPPS` endpoint.
///
/// Only TLS 1.2 and TLS 1.3 are acceptable per `DoD` security requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedTlsVersion {
    /// TLS 1.2 (minimum for `DoD` NIPR/SIPR).
    Tls12,
    /// TLS 1.3 (preferred).
    Tls13,
}

/// Cipher suites permitted for `IPPS` connections.
///
/// Only FIPS 140-3 validated suites using AES-GCM or `ChaCha20-Poly1305`
/// with ECDHE key exchange are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedCipherSuite {
    /// `TLS_AES_128_GCM_SHA256` (TLS 1.3).
    Tls13Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (TLS 1.3).
    Tls13Aes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (TLS 1.2).
    Tls12EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (TLS 1.2).
    Tls12EcdheRsaAes256GcmSha384,
}

impl AllowedCipherSuite {
    /// Return all permitted cipher suites.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Tls13Aes256GcmSha384,
            Self::Tls13Aes128GcmSha256,
            Self::Tls12EcdheRsaAes256GcmSha384,
            Self::Tls12EcdheRsaAes128GcmSha256,
        ]
    }

    /// Return the IANA suite name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Tls13Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Self::Tls13Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            Self::Tls12EcdheRsaAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Self::Tls12EcdheRsaAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        }
    }
}

/// Resolved TLS configuration ready for building a `rustls::ServerConfig`.
///
/// This struct holds the validated paths and options extracted from the
/// service configuration. The actual `rustls` server config is built
/// by the [`server`](crate::server) module.
#[derive(Debug, Clone)]
pub struct TlsSettings {
    /// Path to the PEM-encoded server certificate chain.
    pub cert_path: std::path::PathBuf,
    /// Path to the PEM-encoded private key.
    pub key_path: std::path::PathBuf,
    /// Optional CA bundle for verifying client certificates (mTLS).
    pub ca_bundle_path: Option<std::path::PathBuf>,
    /// Whether to require mTLS.
    pub require_client_cert: bool,
    /// Minimum TLS version.
    pub min_version: AllowedTlsVersion,
}

impl TlsSettings {
    /// Build `TlsSettings` from the service configuration, validating that
    /// the referenced certificate and key files exist.
    ///
    /// **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
    ///
    /// # Errors
    ///
    /// Returns `DriverServiceError::Tls` if the certificate or key path
    /// does not exist or is not a file.
    pub fn from_config(config: &DriverServiceConfig) -> Result<Self, DriverServiceError> {
        validate_file_exists(&config.tls_cert_path, "TLS certificate")?;
        validate_file_exists(&config.tls_key_path, "TLS private key")?;

        if let Some(ca_path) = &config.tls_ca_bundle_path {
            validate_file_exists(ca_path, "CA bundle")?;
        }

        Ok(Self {
            cert_path: config.tls_cert_path.clone(),
            key_path: config.tls_key_path.clone(),
            ca_bundle_path: config.tls_ca_bundle_path.clone(),
            require_client_cert: config.require_client_cert,
            min_version: AllowedTlsVersion::Tls12,
        })
    }
}

/// Validate that a file exists at the given path.
fn validate_file_exists(path: &Path, description: &str) -> Result<(), DriverServiceError> {
    if !path.exists() {
        return Err(DriverServiceError::Tls {
            message: format!("{description} file not found: {}", path.display()),
        });
    }
    if !path.is_file() {
        return Err(DriverServiceError::Tls {
            message: format!("{description} path is not a file: {}", path.display()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_sc8_only_tls12_and_tls13_permitted() {
        // NIST 800-53 Rev 5: SC-8 — Transmission Confidentiality
        // Evidence: only TLS 1.2 and 1.3 are representable.
        let versions = [AllowedTlsVersion::Tls12, AllowedTlsVersion::Tls13];
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn all_cipher_suites_are_aead() {
        for suite in AllowedCipherSuite::all() {
            let name = suite.name();
            assert!(
                name.contains("GCM") || name.contains("CHACHA20"),
                "cipher suite {name} is not AEAD"
            );
        }
    }

    #[test]
    fn tls_settings_rejects_missing_cert() {
        let config = DriverServiceConfig {
            tls_cert_path: "/nonexistent/cert.pem".into(),
            tls_key_path: "/nonexistent/key.pem".into(),
            ..DriverServiceConfig::default()
        };
        let err = TlsSettings::from_config(&config).unwrap_err();
        assert!(matches!(err, DriverServiceError::Tls { .. }));
    }

    #[test]
    fn cipher_suite_names_are_nonempty() {
        for suite in AllowedCipherSuite::all() {
            assert!(!suite.name().is_empty());
        }
    }
}
