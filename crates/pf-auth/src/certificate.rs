// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! X.509 certificate chain validation and EDIPI extraction.
//!
//! **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
//!
//! This module parses X.509 certificates (DER or PEM), validates chains
//! against a trust store, and extracts the EDIPI from the Subject DN
//! (`CN=LAST.FIRST.MI.1234567890`).

use pf_common::identity::Edipi;

use crate::error::AuthError;
use crate::trust_store::TrustStore;

/// A parsed X.509 certificate with its raw DER bytes.
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// The raw DER-encoded certificate bytes.
    der: Vec<u8>,
    /// The Subject DN common name, if present.
    common_name: Option<String>,
    /// The certificate serial number as a hex string.
    serial_hex: String,
    /// Whether the certificate is self-signed (subject == issuer).
    is_self_signed: bool,
}

impl ParsedCertificate {
    /// Parse a DER-encoded X.509 certificate.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::ChainValidation` if the DER bytes are malformed.
    pub fn from_der(der: &[u8]) -> Result<Self, AuthError> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
            AuthError::ChainValidation(format!("failed to parse DER certificate: {e}"))
        })?;

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok().map(String::from));

        let serial_hex = cert.tbs_certificate.serial.to_str_radix(16);

        let is_self_signed = cert.subject() == cert.issuer();

        Ok(Self {
            der: der.to_vec(),
            common_name: cn,
            serial_hex,
            is_self_signed,
        })
    }

    /// Parse a PEM-encoded X.509 certificate.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::ChainValidation` if the PEM is malformed or not a certificate.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, AuthError> {
        use std::io::Cursor;
        use x509_parser::pem::Pem;

        let cursor = Cursor::new(pem_data);
        let (pem, _) = Pem::read(cursor)
            .map_err(|e| AuthError::ChainValidation(format!("failed to parse PEM: {e}")))?;

        if pem.label != "CERTIFICATE" {
            return Err(AuthError::ChainValidation(format!(
                "expected CERTIFICATE PEM block, got: {}",
                pem.label
            )));
        }

        Self::from_der(&pem.contents)
    }

    /// Return the Subject DN common name, if present.
    #[must_use]
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// Return the serial number as a hex string.
    #[must_use]
    pub fn serial_hex(&self) -> &str {
        &self.serial_hex
    }

    /// Return whether this certificate is self-signed.
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.is_self_signed
    }

    /// Return the raw DER bytes.
    #[must_use]
    pub fn der_bytes(&self) -> &[u8] {
        &self.der
    }
}

/// Extract the EDIPI (last 10 digits) from a `DoD` Subject DN common name.
///
/// The `DoD` CN format is `LAST.FIRST.MI.1234567890`. The EDIPI is the
/// trailing 10-digit number.
///
/// **NIST 800-53 Rev 5:** IA-2(12) — Accept PIV Credentials
///
/// # Errors
///
/// Returns `AuthError::EdipiExtraction` if the CN does not contain a
/// valid 10-digit EDIPI suffix.
pub fn extract_edipi_from_cn(cn: &str) -> Result<Edipi, AuthError> {
    // The EDIPI is the last dot-separated segment, exactly 10 digits.
    let last_segment = cn.rsplit('.').next().unwrap_or("");

    Edipi::new(last_segment).map_err(|_| {
        AuthError::EdipiExtraction("CN does not contain a valid 10-digit EDIPI suffix".to_string())
    })
}

/// Validate a certificate chain (leaf + intermediates) against a trust store.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// Validation rules:
/// 1. The chain must be non-empty (leaf is first element).
/// 2. Self-signed leaf certificates are rejected.
/// 3. Every certificate in the chain must be parseable.
/// 4. The chain root must be present in the trust store.
///
/// # Errors
///
/// Returns `AuthError::ChainValidation` if the chain is invalid.
/// Returns `AuthError::TrustStoreUnavailable` if the trust store is empty.
pub fn validate_chain(
    chain: &[ParsedCertificate],
    trust_store: &TrustStore,
) -> Result<(), AuthError> {
    if trust_store.is_empty() {
        return Err(AuthError::TrustStoreUnavailable(
            "trust store contains no anchors — fail closed".to_string(),
        ));
    }

    if chain.is_empty() {
        return Err(AuthError::ChainValidation(
            "certificate chain is empty".to_string(),
        ));
    }

    let leaf = &chain[0];

    // Reject self-signed leaf certificates.
    if leaf.is_self_signed() {
        return Err(AuthError::ChainValidation(
            "self-signed leaf certificate rejected".to_string(),
        ));
    }

    // Verify that the chain terminates at a trusted anchor.
    // The last certificate in the chain should be issued by a trusted root.
    // Safety: chain is verified non-empty above.
    let chain_root = &chain[chain.len() - 1];

    // Check if the chain root itself is in the trust store (by DER bytes),
    // or if any trust anchor issued the chain root.
    if !trust_store.contains_anchor(chain_root.der_bytes()) {
        return Err(AuthError::ChainValidation(
            "chain does not terminate at a trusted anchor".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_edipi_from_standard_dod_cn() {
        let edipi = extract_edipi_from_cn("DOE.JOHN.Q.1234567890").unwrap();
        assert_eq!(edipi.as_str(), "1234567890");
    }

    #[test]
    fn extract_edipi_from_two_part_cn() {
        let edipi = extract_edipi_from_cn("DOE.1234567890").unwrap();
        assert_eq!(edipi.as_str(), "1234567890");
    }

    #[test]
    fn extract_edipi_rejects_missing_digits() {
        let result = extract_edipi_from_cn("DOE.JOHN.Q.ABCDEFGHIJ");
        assert!(result.is_err());
    }

    #[test]
    fn extract_edipi_rejects_empty_cn() {
        let result = extract_edipi_from_cn("");
        assert!(result.is_err());
    }

    #[test]
    fn extract_edipi_rejects_short_number() {
        let result = extract_edipi_from_cn("DOE.JOHN.Q.12345");
        assert!(result.is_err());
    }

    #[test]
    fn nist_ia5_2_rejects_self_signed_leaf() {
        // Build a minimal self-signed cert for testing.
        let params =
            rcgen::CertificateParams::new(vec!["test.local".to_string()]).expect("valid params");
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().expect("keygen"))
            .expect("self-sign");
        let der = cert.der().to_vec();

        let parsed = ParsedCertificate::from_der(&der).expect("parse");
        assert!(parsed.is_self_signed());

        // A trust store containing this cert.
        let ts = TrustStore::from_der_certs(vec![der.clone()]);

        let result = validate_chain(&[parsed], &ts);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("self-signed"));
    }

    #[test]
    fn nist_ia5_2_rejects_empty_chain() {
        let ts = TrustStore::from_der_certs(vec![vec![0u8; 10]]);
        let result = validate_chain(&[], &ts);
        assert!(result.is_err());
    }

    #[test]
    fn nist_sc12_rejects_empty_trust_store() {
        let ts = TrustStore::empty();
        let params =
            rcgen::CertificateParams::new(vec!["test.local".to_string()]).expect("valid params");
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().expect("keygen"))
            .expect("self-sign");
        let der = cert.der().to_vec();
        let parsed = ParsedCertificate::from_der(&der).expect("parse");

        let result = validate_chain(&[parsed], &ts);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("trust store"));
    }

    #[test]
    fn nist_ia2_12_extracts_edipi_from_dod_cn() {
        // NIST 800-53 Rev 5: IA-2(12) — Accept PIV Credentials
        // Evidence: EDIPI is correctly extracted from standard DoD CN format.
        let cn = "DOE.JOHN.Q.1234567890";
        let edipi = extract_edipi_from_cn(cn).unwrap();
        assert_eq!(edipi.as_str(), "1234567890");
    }
}
