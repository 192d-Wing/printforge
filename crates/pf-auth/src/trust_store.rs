// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Trust anchor management for X.509 certificate validation.
//!
//! **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment & Management
//!
//! Trust stores are loaded from PEM bundle files at startup. If the file
//! is missing, empty, or contains no valid certificates, the trust store
//! is empty and all certificate authentication MUST be rejected (fail-closed).

use std::collections::HashSet;
use std::path::Path;

use tracing::{info, warn};

use crate::error::AuthError;

/// A set of trusted root CA certificates (DER-encoded).
///
/// **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment & Management
///
/// The trust store is immutable after construction. To update it, build a
/// new `TrustStore` and swap it in (hot-reload via SIGHUP).
#[derive(Debug, Clone)]
pub struct TrustStore {
    /// DER-encoded trusted root certificates, stored as their SHA-256 digests
    /// for efficient membership testing.
    anchor_digests: HashSet<Vec<u8>>,

    /// Raw DER bytes of each anchor, kept for chain building.
    anchors_der: Vec<Vec<u8>>,
}

impl TrustStore {
    /// Create an empty trust store.
    ///
    /// An empty trust store causes all certificate authentication to fail (fail-closed).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            anchor_digests: HashSet::new(),
            anchors_der: Vec::new(),
        }
    }

    /// Create a trust store from pre-parsed DER-encoded certificates.
    #[must_use]
    pub fn from_der_certs(certs: Vec<Vec<u8>>) -> Self {
        let mut anchor_digests = HashSet::with_capacity(certs.len());
        for cert in &certs {
            anchor_digests.insert(pf_common::crypto::sha256(cert));
        }
        Self {
            anchor_digests,
            anchors_der: certs,
        }
    }

    /// Load trust anchors from a PEM bundle file.
    ///
    /// Parses each PEM `CERTIFICATE` block and stores its DER bytes.
    /// Invalid blocks are skipped with a warning (but at least one valid
    /// certificate must be present for the trust store to be non-empty).
    ///
    /// **NIST 800-53 Rev 5:** SC-12 — If the file is missing or contains
    /// zero valid certificates, the trust store will be empty (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns `AuthError::TrustStoreUnavailable` if the file cannot be read.
    pub fn load_pem_file(path: &Path) -> Result<Self, AuthError> {
        let pem_data = std::fs::read(path).map_err(|e| {
            AuthError::TrustStoreUnavailable(format!(
                "cannot read trust store at {}: {e}",
                path.display()
            ))
        })?;

        let store = Self::from_pem_bytes(&pem_data);

        if store.is_empty() {
            warn!(
                path = %path.display(),
                "trust store loaded but contains zero valid certificates — fail-closed"
            );
        } else {
            info!(
                path = %path.display(),
                count = store.len(),
                "trust store loaded"
            );
        }

        Ok(store)
    }

    /// Parse trust anchors from PEM-encoded bytes.
    ///
    /// Invalid PEM blocks are skipped with a tracing warning.
    #[must_use]
    pub fn from_pem_bytes(pem_data: &[u8]) -> Self {
        use x509_parser::pem::Pem;

        let mut certs = Vec::new();

        // x509_parser's Pem iterator reads successive PEM blocks.
        for pem_result in Pem::iter_from_buffer(pem_data) {
            match pem_result {
                Ok(pem) => {
                    if pem.label == "CERTIFICATE" {
                        certs.push(pem.contents);
                    } else {
                        warn!(label = %pem.label, "skipping non-certificate PEM block");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "skipping malformed PEM block in trust store");
                }
            }
        }

        Self::from_der_certs(certs)
    }

    /// Check whether a certificate (by its DER bytes) is a trust anchor.
    #[must_use]
    pub fn contains_anchor(&self, der: &[u8]) -> bool {
        let digest = pf_common::crypto::sha256(der);
        self.anchor_digests.contains(&digest)
    }

    /// Return the number of trust anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors_der.len()
    }

    /// Return whether the trust store is empty (fail-closed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors_der.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trust_store_is_empty() {
        let ts = TrustStore::empty();
        assert!(ts.is_empty());
        assert_eq!(ts.len(), 0);
    }

    #[test]
    fn from_der_certs_stores_anchors() {
        let cert_der = vec![1u8, 2, 3, 4];
        let ts = TrustStore::from_der_certs(vec![cert_der.clone()]);
        assert_eq!(ts.len(), 1);
        assert!(!ts.is_empty());
        assert!(ts.contains_anchor(&cert_der));
    }

    #[test]
    fn contains_anchor_rejects_unknown_cert() {
        let ts = TrustStore::from_der_certs(vec![vec![1, 2, 3]]);
        assert!(!ts.contains_anchor(&[4, 5, 6]));
    }

    #[test]
    fn nist_sc12_fail_closed_on_missing_file() {
        let result = TrustStore::load_pem_file(Path::new("/nonexistent/trust-store.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn from_pem_bytes_parses_valid_pem() {
        // Generate a self-signed cert to get valid PEM.
        let params =
            rcgen::CertificateParams::new(vec!["test-ca.local".to_string()]).expect("valid params");
        let kp = rcgen::KeyPair::generate().expect("keygen");
        let cert = params.self_signed(&kp).expect("self-sign");
        let pem_str = cert.pem();

        let ts = TrustStore::from_pem_bytes(pem_str.as_bytes());
        assert_eq!(ts.len(), 1);
    }

    #[test]
    fn from_pem_bytes_skips_garbage() {
        let ts = TrustStore::from_pem_bytes(b"this is not a PEM file");
        assert!(ts.is_empty());
    }

    #[test]
    fn nist_sc12_trust_store_round_trip() {
        // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
        // Evidence: A certificate added to the trust store can be found;
        // a certificate NOT in the trust store cannot.
        let params =
            rcgen::CertificateParams::new(vec!["root-ca.local".to_string()]).expect("valid params");
        let kp = rcgen::KeyPair::generate().expect("keygen");
        let cert = params.self_signed(&kp).expect("self-sign");
        let der = cert.der().to_vec();

        let ts = TrustStore::from_der_certs(vec![der.clone()]);
        assert!(ts.contains_anchor(&der));
        assert!(!ts.contains_anchor(b"not-a-cert"));
    }
}
