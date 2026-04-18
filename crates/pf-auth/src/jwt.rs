// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! JWT issuance and validation for authenticated sessions.
//!
//! **NIST 800-53 Rev 5:** IA-5, SC-12 — Authenticator & Key Management
//!
//! Tokens are signed with Ed25519 (`ring`). Two token types:
//! - **Session tokens** (1 hour): web UI sessions
//! - **Printer-scoped tokens** (15 minutes): per-printer release authorization

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use pf_common::identity::Edipi;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::config::JwtConfig;
use crate::error::AuthError;

/// The scope/purpose of a JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    /// Web session token (longer-lived).
    Session,
    /// Printer-scoped release token (short-lived).
    PrinterRelease,
}

/// JWT claims for `PrintForge` tokens.
///
/// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintForgeClaims {
    /// Subject: the user's EDIPI.
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued-at time (Unix timestamp).
    pub iat: i64,
    /// Not-before time (Unix timestamp).
    pub nbf: i64,
    /// Unique token ID (jti) for revocation tracking.
    pub jti: String,
    /// Token scope (session or printer-release).
    pub scope: TokenScope,
    /// User's roles (serialized).
    pub roles: Vec<String>,
    /// Optional printer ID for printer-scoped tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub printer_id: Option<String>,
}

/// A signing key pair for JWT operations.
///
/// The private key is wrapped in `SecretString` to prevent accidental logging.
pub struct JwtKeyPair {
    /// PEM-encoded Ed25519 private key (secret).
    signing_key: SecretString,
    /// PEM-encoded Ed25519 public key.
    verifying_key: Vec<u8>,
}

impl std::fmt::Debug for JwtKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeyPair")
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key_len", &self.verifying_key.len())
            .finish()
    }
}

impl JwtKeyPair {
    /// Create a `JwtKeyPair` from raw Ed25519 key material.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::Configuration` if the key material is invalid.
    pub fn from_ed25519_pem(
        private_pem: SecretString,
        public_pem: Vec<u8>,
    ) -> Result<Self, AuthError> {
        // Validate that the keys are parseable by jsonwebtoken.
        let _enc = EncodingKey::from_ed_pem(private_pem.expose_secret().as_bytes())
            .map_err(|e| AuthError::Configuration(format!("invalid Ed25519 private key: {e}")))?;
        let _dec = DecodingKey::from_ed_pem(&public_pem)
            .map_err(|e| AuthError::Configuration(format!("invalid Ed25519 public key: {e}")))?;

        Ok(Self {
            signing_key: private_pem,
            verifying_key: public_pem,
        })
    }

    /// Return the encoding (signing) key.
    fn encoding_key(&self) -> Result<EncodingKey, AuthError> {
        EncodingKey::from_ed_pem(self.signing_key.expose_secret().as_bytes())
            .map_err(|e| AuthError::JwtError(format!("signing key error: {e}")))
    }

    /// Return the decoding (verifying) key.
    fn decoding_key(&self) -> Result<DecodingKey, AuthError> {
        DecodingKey::from_ed_pem(&self.verifying_key)
            .map_err(|e| AuthError::JwtError(format!("verifying key error: {e}")))
    }
}

/// Issue a signed JWT for the given user and scope.
///
/// **NIST 800-53 Rev 5:** IA-5, SC-12
///
/// # Errors
///
/// Returns `AuthError::JwtError` if token signing fails.
pub fn issue_token(
    config: &JwtConfig,
    key_pair: &JwtKeyPair,
    edipi: &Edipi,
    roles: &[String],
    scope: TokenScope,
    printer_id: Option<String>,
) -> Result<String, AuthError> {
    let now = Utc::now();
    let ttl = match scope {
        TokenScope::Session => Duration::from_std(config.session_ttl)
            .map_err(|e| AuthError::Configuration(format!("invalid session TTL: {e}")))?,
        TokenScope::PrinterRelease => Duration::from_std(config.printer_ttl)
            .map_err(|e| AuthError::Configuration(format!("invalid printer TTL: {e}")))?,
    };
    let exp = now + ttl;

    let claims = PrintForgeClaims {
        sub: edipi.as_str().to_string(),
        iss: config.issuer.clone(),
        aud: config.audience.clone(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        scope,
        roles: roles.to_vec(),
        printer_id,
    };

    let header = Header::new(Algorithm::EdDSA);
    let encoding_key = key_pair.encoding_key()?;

    encode(&header, &claims, &encoding_key)
        .map_err(|e| AuthError::JwtError(format!("failed to sign token: {e}")))
}

/// Validate and decode a `PrintForge` JWT.
///
/// **NIST 800-53 Rev 5:** IA-5 — Authenticator Management
///
/// # Errors
///
/// Returns `AuthError::TokenExpired` if the token has expired.
/// Returns `AuthError::JwtError` if the token is malformed or the signature is invalid.
pub fn validate_token(
    config: &JwtConfig,
    key_pair: &JwtKeyPair,
    token: &str,
) -> Result<PrintForgeClaims, AuthError> {
    let decoding_key = key_pair.decoding_key()?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.audience]);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let token_data =
        decode::<PrintForgeClaims>(token, &decoding_key, &validation).map_err(|e| {
            if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                AuthError::TokenExpired
            } else {
                AuthError::JwtError(format!("token validation failed: {e}"))
            }
        })?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate an Ed25519 key pair for testing using `ring`.
    fn test_key_pair() -> JwtKeyPair {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");

        // Convert PKCS#8 to PEM for jsonwebtoken.
        let pkcs8_bytes = pkcs8_doc.as_ref();
        let private_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            base64::engine::general_purpose::STANDARD.encode(pkcs8_bytes)
        );

        // Extract the public key.
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes).expect("parse pkcs8");
        let public_key_bytes = kp.public_key().as_ref();

        // Wrap in SPKI DER then PEM.
        // Ed25519 SPKI prefix: 30 2a 30 05 06 03 2b 65 70 03 21 00
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(public_key_bytes);

        let public_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64::engine::general_purpose::STANDARD.encode(&spki)
        );

        JwtKeyPair::from_ed25519_pem(SecretString::from(private_pem), public_pem.into_bytes())
            .expect("valid key pair")
    }

    use base64::Engine;

    #[test]
    fn issue_and_validate_session_token() {
        let config = JwtConfig::default();
        let kp = test_key_pair();
        let edipi = Edipi::new("1234567890").unwrap();

        let token = issue_token(
            &config,
            &kp,
            &edipi,
            &["User".to_string()],
            TokenScope::Session,
            None,
        )
        .unwrap();

        let claims = validate_token(&config, &kp, &token).unwrap();
        assert_eq!(claims.sub, "1234567890");
        assert_eq!(claims.scope, TokenScope::Session);
        assert!(claims.printer_id.is_none());
    }

    #[test]
    fn issue_printer_scoped_token() {
        let config = JwtConfig::default();
        let kp = test_key_pair();
        let edipi = Edipi::new("1234567890").unwrap();

        let token = issue_token(
            &config,
            &kp,
            &edipi,
            &["User".to_string()],
            TokenScope::PrinterRelease,
            Some("PRN-0042".to_string()),
        )
        .unwrap();

        let claims = validate_token(&config, &kp, &token).unwrap();
        assert_eq!(claims.scope, TokenScope::PrinterRelease);
        assert_eq!(claims.printer_id.as_deref(), Some("PRN-0042"));
    }

    #[test]
    fn nist_ia5_token_has_short_lifetime() {
        // NIST 800-53 Rev 5: IA-5 — Authenticator Management
        // Evidence: Session tokens expire within configured TTL.
        let config = JwtConfig::default();
        let kp = test_key_pair();
        let edipi = Edipi::new("1234567890").unwrap();

        let token = issue_token(
            &config,
            &kp,
            &edipi,
            &["User".to_string()],
            TokenScope::Session,
            None,
        )
        .unwrap();

        let claims = validate_token(&config, &kp, &token).unwrap();
        let lifetime = claims.exp - claims.iat;
        // Session TTL is 1 hour = 3600 seconds.
        assert_eq!(lifetime, 3600);
    }

    #[test]
    fn nist_ia5_printer_token_has_15min_lifetime() {
        // NIST 800-53 Rev 5: IA-5 — Authenticator Management
        // Evidence: Printer-scoped tokens expire within 15 minutes.
        let config = JwtConfig::default();
        let kp = test_key_pair();
        let edipi = Edipi::new("1234567890").unwrap();

        let token = issue_token(
            &config,
            &kp,
            &edipi,
            &["User".to_string()],
            TokenScope::PrinterRelease,
            None,
        )
        .unwrap();

        let claims = validate_token(&config, &kp, &token).unwrap();
        let lifetime = claims.exp - claims.iat;
        assert_eq!(lifetime, 900);
    }

    #[test]
    fn jwt_key_pair_debug_redacts_secret() {
        let kp = test_key_pair();
        let debug = format!("{kp:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("PRIVATE KEY"));
    }

    #[test]
    fn validate_rejects_tampered_token() {
        let config = JwtConfig::default();
        let kp = test_key_pair();
        let edipi = Edipi::new("1234567890").unwrap();

        let mut token = issue_token(
            &config,
            &kp,
            &edipi,
            &["User".to_string()],
            TokenScope::Session,
            None,
        )
        .unwrap();

        // Tamper with the last character of the signature.
        let last = token.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        token.push(replacement);

        let result = validate_token(&config, &kp, &token);
        assert!(result.is_err());
    }
}
