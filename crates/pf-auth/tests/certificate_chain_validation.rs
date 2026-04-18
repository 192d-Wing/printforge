// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for X.509 certificate chain validation and EDIPI extraction.
//!
//! **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication,
//! IA-2(12) — Accept PIV Credentials
//!
//! Uses `rcgen` to generate synthetic test CA hierarchies. No real DoD/NSS
//! PKI material is used.

#![forbid(unsafe_code)]

use pf_auth::certificate::{ParsedCertificate, extract_edipi_from_cn, validate_chain};
use pf_auth::trust_store::TrustStore;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

// ---------------------------------------------------------------------------
// Test CA hierarchy helpers
// ---------------------------------------------------------------------------

/// Build a self-signed root CA.
fn build_root_ca(cn: &str) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("valid params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let kp = KeyPair::generate().expect("keygen");
    let cert = params.self_signed(&kp).expect("self-sign");
    (cert, kp)
}

/// Build an intermediate CA signed by a parent.
fn build_intermediate_ca(
    cn: &str,
    parent_cert: &rcgen::Certificate,
    parent_kp: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("valid params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let kp = KeyPair::generate().expect("keygen");
    let cert = params.signed_by(&kp, parent_cert, parent_kp).expect("sign");
    (cert, kp)
}

/// Build a leaf certificate signed by a CA.
fn build_leaf(
    cn: &str,
    ca_cert: &rcgen::Certificate,
    ca_kp: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("valid params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::NoCa;
    let kp = KeyPair::generate().expect("keygen");
    let cert = params.signed_by(&kp, ca_cert, ca_kp).expect("sign");
    (cert, kp)
}

/// Build a complete 3-tier test PKI: root -> intermediate -> leaf.
fn build_test_pki() -> (
    rcgen::Certificate,
    KeyPair,
    rcgen::Certificate,
    KeyPair,
    rcgen::Certificate,
    KeyPair,
) {
    let (root_cert, root_kp) = build_root_ca("Test Root CA");
    let (int_cert, int_kp) = build_intermediate_ca("Test Intermediate CA", &root_cert, &root_kp);
    let (leaf_cert, leaf_kp) =
        build_leaf("DOE.JOHN.Q.1234567890", &int_cert, &int_kp);
    (root_cert, root_kp, int_cert, int_kp, leaf_cert, leaf_kp)
}

// ---------------------------------------------------------------------------
// Chain validation tests — NIST IA-5(2)
// ---------------------------------------------------------------------------

#[test]
fn nist_ia5_2_validates_valid_certificate_chain() {
    // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
    // Evidence: A valid 3-tier chain (leaf → intermediate → root) passes
    // validation when the root is in the trust store.
    let (root_cert, _, int_cert, _, leaf_cert, _) = build_test_pki();

    let root_der = root_cert.der().to_vec();
    let int_der = int_cert.der().to_vec();
    let leaf_der = leaf_cert.der().to_vec();

    let trust_store = TrustStore::from_der_certs(vec![root_der]);

    let parsed_leaf = ParsedCertificate::from_der(&leaf_der).expect("parse leaf");
    let parsed_int = ParsedCertificate::from_der(&int_der).expect("parse intermediate");

    // Chain: [leaf, intermediate] with root in trust store (as the intermediate's issuer).
    // Since validate_chain checks if the last cert in chain is in the trust store,
    // we include the root in the chain for proper termination.
    let root_der2 = root_cert.der().to_vec();
    let parsed_root = ParsedCertificate::from_der(&root_der2).expect("parse root");
    let result = validate_chain(&[parsed_leaf, parsed_int, parsed_root], &trust_store);
    assert!(result.is_ok(), "valid chain should pass: {result:?}");
}

#[test]
fn nist_ia5_2_validates_two_tier_chain() {
    // Valid chain with just leaf + root (no intermediate).
    let (root_cert, root_kp) = build_root_ca("Test Root CA 2");
    let (leaf_cert, _) = build_leaf("DOE.JANE.M.9876543210", &root_cert, &root_kp);

    let root_der = root_cert.der().to_vec();
    let leaf_der = leaf_cert.der().to_vec();

    let trust_store = TrustStore::from_der_certs(vec![root_der.clone()]);

    let parsed_leaf = ParsedCertificate::from_der(&leaf_der).expect("parse leaf");
    let parsed_root = ParsedCertificate::from_der(&root_der).expect("parse root");

    let result = validate_chain(&[parsed_leaf, parsed_root], &trust_store);
    assert!(result.is_ok(), "two-tier chain should pass: {result:?}");
}

#[test]
fn nist_ia5_2_rejects_self_signed_certificate() {
    // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
    // Evidence: Self-signed leaf certificates are rejected even when
    // present in the trust store.
    let params = CertificateParams::new(vec!["test.local".to_string()]).expect("valid params");
    let kp = KeyPair::generate().expect("keygen");
    let cert = params.self_signed(&kp).expect("self-sign");
    let der = cert.der().to_vec();

    let trust_store = TrustStore::from_der_certs(vec![der.clone()]);
    let parsed = ParsedCertificate::from_der(&der).expect("parse");

    assert!(parsed.is_self_signed());
    let result = validate_chain(&[parsed], &trust_store);
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("self-signed"));
}

#[test]
fn nist_ia5_2_rejects_wrong_trust_store() {
    // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
    // Evidence: A chain from CA-A is rejected when only CA-B is in the trust store.
    let (untrusted_root, untrusted_kp) = build_root_ca("Root CA A");
    let (leaf_cert, _) = build_leaf("DOE.JOHN.Q.1234567890", &untrusted_root, &untrusted_kp);

    let (trusted_root, _) = build_root_ca("Root CA B");
    let trusted_der = trusted_root.der().to_vec();

    // Trust store has only the trusted root, but chain is from the untrusted one.
    let trust_store = TrustStore::from_der_certs(vec![trusted_der]);

    let leaf_der = leaf_cert.der().to_vec();
    let untrusted_der = untrusted_root.der().to_vec();
    let parsed_leaf = ParsedCertificate::from_der(&leaf_der).expect("parse leaf");
    let parsed_root = ParsedCertificate::from_der(&untrusted_der).expect("parse root");

    let result = validate_chain(&[parsed_leaf, parsed_root], &trust_store);
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("trusted anchor"));
}

#[test]
fn nist_ia5_2_rejects_empty_chain() {
    // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
    // Evidence: An empty certificate chain is rejected.
    let (root_cert, _) = build_root_ca("Test Root");
    let trust_store = TrustStore::from_der_certs(vec![root_cert.der().to_vec()]);

    let result = validate_chain(&[], &trust_store);
    assert!(result.is_err());
}

#[test]
fn nist_sc12_rejects_empty_trust_store() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: An empty trust store causes fail-closed behavior — all
    // certificate authentication is rejected.
    let trust_store = TrustStore::empty();

    let (root_cert, root_kp) = build_root_ca("Root CA");
    let (leaf_cert, _) = build_leaf("DOE.JOHN.Q.1234567890", &root_cert, &root_kp);
    let parsed = ParsedCertificate::from_der(leaf_cert.der()).expect("parse");

    let result = validate_chain(&[parsed], &trust_store);
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("trust store"));
}

// ---------------------------------------------------------------------------
// EDIPI extraction tests — NIST IA-2
// ---------------------------------------------------------------------------

#[test]
fn nist_ia2_extracts_edipi_from_subject_dn() {
    // NIST 800-53 Rev 5: IA-2 — Identification and Authentication
    // Evidence: EDIPI is correctly extracted from various DoD CN formats.
    let edipi = extract_edipi_from_cn("DOE.JOHN.Q.1234567890").unwrap();
    assert_eq!(edipi.as_str(), "1234567890");

    // Two-part CN (no middle initial).
    let edipi2 = extract_edipi_from_cn("DOE.1234567890").unwrap();
    assert_eq!(edipi2.as_str(), "1234567890");

    // Five-part CN (suffix/title).
    let edipi3 = extract_edipi_from_cn("DOE.JOHN.Q.JR.1234567890").unwrap();
    assert_eq!(edipi3.as_str(), "1234567890");
}

#[test]
fn nist_ia2_rejects_invalid_edipi_format() {
    // NIST 800-53 Rev 5: IA-2 — Identification and Authentication
    // Evidence: Non-numeric, wrong-length, and empty CNs are rejected.

    // Non-numeric last segment.
    assert!(extract_edipi_from_cn("DOE.JOHN.Q.ABCDEFGHIJ").is_err());

    // Too short.
    assert!(extract_edipi_from_cn("DOE.JOHN.Q.12345").is_err());

    // Too long.
    assert!(extract_edipi_from_cn("DOE.JOHN.Q.12345678901").is_err());

    // Empty CN.
    assert!(extract_edipi_from_cn("").is_err());

    // No dots — single segment that isn't 10 digits.
    assert!(extract_edipi_from_cn("DOE").is_err());
}

// ---------------------------------------------------------------------------
// ParsedCertificate construction tests
// ---------------------------------------------------------------------------

#[test]
fn parsed_certificate_extracts_common_name() {
    let (root_cert, root_kp) = build_root_ca("Test CA");
    let (leaf_cert, _) = build_leaf("DOE.JOHN.Q.1234567890", &root_cert, &root_kp);
    let parsed = ParsedCertificate::from_der(leaf_cert.der()).expect("parse");
    assert_eq!(parsed.common_name(), Some("DOE.JOHN.Q.1234567890"));
    assert!(!parsed.is_self_signed());
}

#[test]
fn parsed_certificate_from_pem() {
    let (root_cert, _) = build_root_ca("Test PEM CA");
    let pem_str = root_cert.pem();
    let parsed = ParsedCertificate::from_pem(pem_str.as_bytes()).expect("parse PEM");
    assert_eq!(parsed.common_name(), Some("Test PEM CA"));
    assert!(parsed.is_self_signed());
}

#[test]
fn parsed_certificate_rejects_malformed_der() {
    let result = ParsedCertificate::from_der(b"not a certificate");
    assert!(result.is_err());
}
