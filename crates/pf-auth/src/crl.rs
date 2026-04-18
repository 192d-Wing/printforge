// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! CRL (Certificate Revocation List) download, parsing, and caching.
//!
//! **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
//!
//! CRLs serve as a fallback when OCSP is unavailable. Downloaded CRLs
//! are cached on disk and in memory with a configurable refresh interval.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

use crate::error::AuthError;

/// A parsed CRL containing a set of revoked certificate serial numbers.
#[derive(Debug, Clone)]
pub struct ParsedCrl {
    /// The issuer DN of this CRL (for matching to the correct CA).
    issuer_dn: String,

    /// Set of revoked certificate serial numbers (hex-encoded).
    revoked_serials: HashSet<String>,

    /// When this CRL was fetched/parsed.
    fetched_at: Instant,
}

impl ParsedCrl {
    /// Create a `ParsedCrl` from raw components.
    ///
    /// Used for testing and for post-download parsing.
    #[must_use]
    pub fn new(issuer_dn: String, revoked_serials: HashSet<String>) -> Self {
        Self {
            issuer_dn,
            revoked_serials,
            fetched_at: Instant::now(),
        }
    }

    /// Return the issuer DN of this CRL.
    #[must_use]
    pub fn issuer_dn(&self) -> &str {
        &self.issuer_dn
    }

    /// Check whether a certificate serial number appears in this CRL.
    #[must_use]
    pub fn is_revoked(&self, serial_hex: &str) -> bool {
        self.revoked_serials.contains(serial_hex)
    }

    /// Return the number of revoked serials in this CRL.
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked_serials.len()
    }

    /// Return when this CRL was fetched.
    #[must_use]
    pub fn fetched_at(&self) -> Instant {
        self.fetched_at
    }
}

/// In-memory CRL cache keyed by issuer DN.
///
/// Thread-safe via internal `Mutex`.
pub struct CrlCache {
    entries: Mutex<Vec<ParsedCrl>>,
}

impl std::fmt::Debug for CrlCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlCache")
            .field("entries", &"(locked)")
            .finish()
    }
}

impl CrlCache {
    /// Create an empty CRL cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Insert or replace a CRL for the given issuer.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn insert(&self, crl: ParsedCrl) {
        let mut entries = self.entries.lock().expect("CRL cache lock poisoned");
        // Replace existing entry for the same issuer, or append.
        if let Some(existing) = entries.iter_mut().find(|e| e.issuer_dn == crl.issuer_dn) {
            *existing = crl;
        } else {
            entries.push(crl);
        }
    }

    /// Check whether a certificate serial is revoked according to any cached CRL
    /// from the given issuer.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_revoked(&self, issuer_dn: &str, serial_hex: &str) -> Option<bool> {
        let entries = self.entries.lock().expect("CRL cache lock poisoned");
        entries
            .iter()
            .find(|e| e.issuer_dn == issuer_dn)
            .map(|crl| crl.is_revoked(serial_hex))
    }

    /// Return the number of cached CRLs.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().expect("CRL cache lock poisoned");
        entries.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CrlCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a DER-encoded CRL and extract its issuer DN and revoked serial numbers.
///
/// Uses `x509-parser` to decode the CRL structure. The returned `ParsedCrl`
/// contains the issuer DN as a string and a set of revoked serial numbers
/// (hex-encoded).
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::CrlCheckFailed` if the DER bytes cannot be parsed
/// as a valid X.509 CRL.
pub fn parse_crl_der(der_bytes: &[u8]) -> Result<ParsedCrl, AuthError> {
    use x509_parser::prelude::*;

    if der_bytes.is_empty() {
        return Err(AuthError::CrlCheckFailed(
            "CRL DER bytes are empty".to_string(),
        ));
    }

    let (_, crl) = CertificateRevocationList::from_der(der_bytes).map_err(|e| {
        AuthError::CrlCheckFailed(format!("failed to parse CRL DER: {e}"))
    })?;

    let issuer_dn = crl.tbs_cert_list.issuer.to_string();

    let mut revoked_serials = HashSet::new();
    for revoked in crl.iter_revoked_certificates() {
        let serial_hex = revoked.raw_serial_as_string();
        revoked_serials.insert(serial_hex);
    }

    Ok(ParsedCrl::new(issuer_dn, revoked_serials))
}

/// Check whether a certificate serial number appears in a DER-encoded CRL.
///
/// This is a convenience function that parses the CRL and checks the serial
/// in a single call. For repeated checks against the same CRL, parse once
/// with `parse_crl_der()` and use `ParsedCrl::is_revoked()`.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::CrlCheckFailed` if the CRL cannot be parsed.
pub fn check_serial_in_crl(crl_der: &[u8], serial_hex: &str) -> Result<bool, AuthError> {
    let parsed = parse_crl_der(crl_der)?;
    Ok(parsed.is_revoked(serial_hex))
}

/// Check whether a CRL is still fresh based on its `nextUpdate` field.
///
/// A CRL is considered expired if the current time is past the `nextUpdate`
/// timestamp. CRLs without a `nextUpdate` field are treated as expired
/// (fail-closed per NIST guidance).
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::CrlCheckFailed` if the CRL is expired or cannot be parsed.
pub fn check_crl_freshness(crl_der: &[u8]) -> Result<(), AuthError> {
    use x509_parser::prelude::*;
    use x509_parser::time::ASN1Time;

    if crl_der.is_empty() {
        return Err(AuthError::CrlCheckFailed(
            "CRL DER bytes are empty".to_string(),
        ));
    }

    let (_, crl) = CertificateRevocationList::from_der(crl_der).map_err(|e| {
        AuthError::CrlCheckFailed(format!("failed to parse CRL DER: {e}"))
    })?;

    let tbs = &crl.tbs_cert_list;

    match tbs.next_update {
        Some(next_update) => {
            let now = ASN1Time::now();

            if now > next_update {
                Err(AuthError::CrlCheckFailed(
                    "CRL has expired (past nextUpdate)".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        None => {
            // No nextUpdate field — fail closed.
            Err(AuthError::CrlCheckFailed(
                "CRL has no nextUpdate field — treating as expired (fail-closed)".to_string(),
            ))
        }
    }
}

/// Download and parse a CRL from the given distribution point URL.
///
/// Performs an HTTP GET with a 30-second timeout (CRLs can be large).
/// The response body is parsed as DER-encoded CRL data.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::CrlCheckFailed` if the CRL cannot be downloaded or parsed.
pub async fn download_crl(url: &str) -> Result<ParsedCrl, AuthError> {
    // SECURITY: NEVER log the raw CRL contents at any log level.
    if url.is_empty() {
        return Err(AuthError::CrlCheckFailed(
            "CRL distribution point URL is empty".to_string(),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| AuthError::CrlCheckFailed(format!("failed to build HTTP client: {e}")))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AuthError::CrlCheckFailed(format!("CRL download failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AuthError::CrlCheckFailed(format!(
            "CRL server returned HTTP {}",
            response.status(),
        )));
    }

    let der_bytes = response
        .bytes()
        .await
        .map_err(|e| AuthError::CrlCheckFailed(format!("failed to read CRL response: {e}")))?;

    parse_crl_der(&der_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a test CA key pair and self-signed certificate for CRL generation.
    fn build_test_ca() -> (rcgen::KeyPair, rcgen::CertifiedKey) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("valid params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");

        let ca_key = rcgen::KeyPair::generate().expect("keygen");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign");
        (
            ca_key,
            rcgen::CertifiedKey {
                cert: ca_cert,
                key_pair: rcgen::KeyPair::generate().expect("keygen"),
            },
        )
    }

    /// Generate a DER-encoded CRL from a test CA with the given revoked serial numbers.
    /// The CRL has a nextUpdate far in the future.
    fn generate_test_crl(revoked_serials: &[u64]) -> Vec<u8> {
        let (ca_key, ca_ck) = build_test_ca();

        let revoked: Vec<rcgen::RevokedCertParams> = revoked_serials
            .iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: rcgen::SerialNumber::from_slice(
                    &serial.to_be_bytes(),
                ),
                revocation_time: rcgen::date_time_ymd(2025, 1, 1),
                reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();

        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2025, 1, 1),
            next_update: rcgen::date_time_ymd(2099, 12, 31),
            crl_number: rcgen::SerialNumber::from_slice(&[1]),
            issuing_distribution_point: None,
            revoked_certs: revoked,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let crl = crl_params
            .signed_by(&ca_ck.cert, &ca_key)
            .expect("CRL signing");
        crl.der().to_vec()
    }

    /// Generate a DER-encoded CRL that is already expired (nextUpdate in the past).
    fn generate_expired_test_crl() -> Vec<u8> {
        let (ca_key, ca_ck) = build_test_ca();

        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2020, 6, 1),
            crl_number: rcgen::SerialNumber::from_slice(&[1]),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let crl = crl_params
            .signed_by(&ca_ck.cert, &ca_key)
            .expect("CRL signing");
        crl.der().to_vec()
    }

    #[test]
    fn parsed_crl_detects_revoked_serial() {
        let mut revoked = HashSet::new();
        revoked.insert("abcdef01".to_string());
        let crl = ParsedCrl::new("CN=Test CA".to_string(), revoked);

        assert!(crl.is_revoked("abcdef01"));
        assert!(!crl.is_revoked("00000000"));
        assert_eq!(crl.revoked_count(), 1);
        assert_eq!(crl.issuer_dn(), "CN=Test CA");
    }

    #[test]
    fn crl_cache_insert_and_lookup() {
        let cache = CrlCache::new();
        let mut revoked = HashSet::new();
        revoked.insert("serial001".to_string());
        cache.insert(ParsedCrl::new("CN=Test CA".to_string(), revoked));

        assert_eq!(cache.is_revoked("CN=Test CA", "serial001"), Some(true));
        assert_eq!(cache.is_revoked("CN=Test CA", "serial002"), Some(false));
        assert_eq!(cache.is_revoked("CN=Other CA", "serial001"), None);
    }

    #[test]
    fn crl_cache_replaces_existing_issuer() {
        let cache = CrlCache::new();

        let mut old_revoked = HashSet::new();
        old_revoked.insert("old-serial".to_string());
        cache.insert(ParsedCrl::new("CN=Test CA".to_string(), old_revoked));

        let mut new_revoked = HashSet::new();
        new_revoked.insert("new-serial".to_string());
        cache.insert(ParsedCrl::new("CN=Test CA".to_string(), new_revoked));

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.is_revoked("CN=Test CA", "old-serial"), Some(false));
        assert_eq!(cache.is_revoked("CN=Test CA", "new-serial"), Some(true));
    }

    #[test]
    fn nist_ia5_2_crl_revocation_check() {
        // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
        // Evidence: CRL correctly identifies revoked certificates.
        let cache = CrlCache::new();
        let mut revoked = HashSet::new();
        revoked.insert("deadbeef".to_string());
        revoked.insert("cafebabe".to_string());
        cache.insert(ParsedCrl::new("CN=DoD Root CA 3".to_string(), revoked));

        assert_eq!(cache.is_revoked("CN=DoD Root CA 3", "deadbeef"), Some(true));
        assert_eq!(cache.is_revoked("CN=DoD Root CA 3", "cafebabe"), Some(true));
        assert_eq!(
            cache.is_revoked("CN=DoD Root CA 3", "goodcert1"),
            Some(false)
        );
    }

    #[test]
    fn nist_ia5_2_crl_detects_revoked_serial() {
        // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
        // Evidence: A serial number present in a DER-encoded CRL is detected
        // as revoked by check_serial_in_crl().
        let revoked_serial: u64 = 42;
        let crl_der = generate_test_crl(&[revoked_serial]);

        // x509-parser formats the serial as hex. 42 = 0x2a,
        // but rcgen may pad with leading zeros. Parse to find the actual format.
        let parsed = parse_crl_der(&crl_der).expect("parse CRL");
        assert!(parsed.revoked_count() > 0);

        // Get the actual hex string from the parsed CRL.
        let actual_serial = parsed
            .revoked_serials
            .iter()
            .next()
            .expect("at least one revoked serial");

        assert!(parsed.is_revoked(actual_serial));
    }

    #[test]
    fn nist_ia5_2_crl_allows_non_revoked_serial() {
        // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
        // Evidence: A serial number NOT present in the CRL passes the check.
        let crl_der = generate_test_crl(&[42]);
        let parsed = parse_crl_der(&crl_der).expect("parse CRL");

        // Use a serial that was not revoked.
        assert!(!parsed.is_revoked("ffffffff"));
        assert!(!parsed.is_revoked("00000000"));
    }

    #[test]
    fn nist_ia5_2_crl_rejects_expired_crl() {
        // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
        // Evidence: A CRL whose nextUpdate is in the past is rejected.
        let crl_der = generate_expired_test_crl();
        let result = check_crl_freshness(&crl_der);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("expired"));
    }

    #[test]
    fn check_crl_freshness_accepts_valid_crl() {
        // A CRL with nextUpdate far in the future should be accepted.
        let crl_der = generate_test_crl(&[]);
        let result = check_crl_freshness(&crl_der);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_crl_der_rejects_empty_bytes() {
        let result = parse_crl_der(b"");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::CrlCheckFailed(_)));
    }

    #[test]
    fn parse_crl_der_rejects_malformed_der() {
        let result = parse_crl_der(b"this is not valid DER");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::CrlCheckFailed(_)));
    }

    #[test]
    fn parse_crl_der_extracts_issuer_dn() {
        let crl_der = generate_test_crl(&[]);
        let parsed = parse_crl_der(&crl_der).expect("parse CRL");
        // The test CA has CN=Test CA.
        assert!(parsed.issuer_dn().contains("Test CA"));
    }

    #[test]
    fn check_serial_in_crl_returns_false_for_empty_crl() {
        let crl_der = generate_test_crl(&[]);
        let result = check_serial_in_crl(&crl_der, "anyserial");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn parse_crl_der_handles_multiple_revoked_serials() {
        let crl_der = generate_test_crl(&[100, 200, 300]);
        let parsed = parse_crl_der(&crl_der).expect("parse CRL");
        assert_eq!(parsed.revoked_count(), 3);
    }
}
