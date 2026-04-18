// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for HTTP transport in OCSP, CRL, and OIDC modules.
//!
//! Uses `wiremock` to mock HTTP endpoints so that tests do not require
//! external network access.

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use pf_auth::error::AuthError;
use pf_auth::ocsp::{check_ocsp_status, OcspStatus};
use pf_auth::crl::download_crl;
use pf_auth::oidc::{
    exchange_code, OidcCallback, OidcFlowState,
};
use pf_auth::config::OidcConfig;

use std::time::Duration;
use url::Url;

// ---------------------------------------------------------------------------
// OCSP transport tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ocsp_request_posts_to_responder() {
    // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
    // Evidence: OCSP request is sent via HTTP POST with correct Content-Type.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("Content-Type", "application/ocsp-request"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ocsp-response-bytes"))
        .expect(1)
        .mount(&server)
        .await;

    let result = check_ocsp_status("abc123", b"issuer-der", &server.uri()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), OcspStatus::Good);
}

#[tokio::test]
async fn test_ocsp_request_handles_timeout() {
    // Verify that a slow OCSP responder triggers a timeout error.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let result = check_ocsp_status("abc123", b"issuer-der", &server.uri()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::OcspCheckFailed(_)));
}

#[tokio::test]
async fn test_ocsp_request_handles_http_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let result = check_ocsp_status("abc123", b"issuer-der", &server.uri()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::OcspCheckFailed(_)));
}

// ---------------------------------------------------------------------------
// CRL transport tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_crl_download_returns_bytes() {
    // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
    // Evidence: CRL is downloaded via HTTP GET and DER bytes are parsed.
    let server = MockServer::start().await;

    // Generate a valid test CRL using rcgen.
    let crl_der = generate_test_crl_der();

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(crl_der))
        .expect(1)
        .mount(&server)
        .await;

    let result = download_crl(&server.uri()).await;
    assert!(result.is_ok());
    let parsed = result.unwrap();
    // The test CRL has CN=Test CA as issuer.
    assert!(parsed.issuer_dn().contains("Test CA"));
}

#[tokio::test]
async fn test_crl_download_handles_http_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let result = download_crl(&server.uri()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::CrlCheckFailed(_)));
}

#[tokio::test]
async fn test_crl_download_rejects_empty_url() {
    let result = download_crl("").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::CrlCheckFailed(_)));
}

// ---------------------------------------------------------------------------
// OIDC token exchange transport tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_oidc_token_exchange_posts_form() {
    // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
    // Evidence: Token exchange sends correct form params and parses response.
    let server = MockServer::start().await;

    // Build a minimal JWT with claims in the payload.
    let id_token = build_test_jwt(&serde_json::json!({
        "sub": "1234567890",
        "preferred_username": "DOE.JOHN.Q.1234567890",
        "name": "John Q Doe",
        "nonce": "test-nonce-xyz",
        "groups": []
    }));

    let token_response = serde_json::json!({
        "id_token": id_token,
        "access_token": "at-test-access-token",
        "refresh_token": "rt-test-refresh-token"
    });

    Mock::given(method("POST"))
        .and(path("/tenant1/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
        .expect(1)
        .mount(&server)
        .await;

    let config = OidcConfig {
        issuer_url: Url::parse(&format!("{}/tenant1", server.uri())).unwrap(),
        client_id: "test-client-id".to_string(),
        redirect_uri: Url::parse("https://printforge.local/callback").unwrap(),
        scopes: vec!["openid".to_string()],
    };

    let callback = OidcCallback {
        code: "auth-code-abc".to_string(),
        state: "test-state-abc".to_string(),
    };

    let flow_state = OidcFlowState {
        state: "test-state-abc".to_string(),
        nonce: "test-nonce-xyz".to_string(),
        pkce_verifier: Some("test-verifier-123".to_string()),
        return_url: None,
    };

    let result = exchange_code(&config, &callback, &flow_state).await;
    assert!(result.is_ok());
    let (tokens, identity) = result.unwrap();
    assert_eq!(identity.edipi.as_str(), "1234567890");
    assert_eq!(identity.name, "John Q Doe");
    assert!(!tokens.access_token.is_empty());
    assert!(tokens.refresh_token.is_some());
}

#[tokio::test]
async fn test_oidc_rejects_http_error() {
    // Verify that an HTTP error from the token endpoint produces AuthError.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/tenant1/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant"
        })))
        .mount(&server)
        .await;

    let config = OidcConfig {
        issuer_url: Url::parse(&format!("{}/tenant1", server.uri())).unwrap(),
        client_id: "test-client-id".to_string(),
        redirect_uri: Url::parse("https://printforge.local/callback").unwrap(),
        scopes: vec!["openid".to_string()],
    };

    let callback = OidcCallback {
        code: "bad-code".to_string(),
        state: "test-state".to_string(),
    };

    let flow_state = OidcFlowState {
        state: "test-state".to_string(),
        nonce: "test-nonce".to_string(),
        pkce_verifier: Some("test-verifier".to_string()),
        return_url: None,
    };

    let result = exchange_code(&config, &callback, &flow_state).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::OidcError(_)));
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate a DER-encoded CRL from a test CA with no revoked certs.
fn generate_test_crl_der() -> Vec<u8> {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("valid params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");

    let ca_key = rcgen::KeyPair::generate().expect("keygen");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign");
    let ca_ck = rcgen::CertifiedKey {
        cert: ca_cert,
        key_pair: rcgen::KeyPair::generate().expect("keygen"),
    };

    let crl_params = rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2025, 1, 1),
        next_update: rcgen::date_time_ymd(2099, 12, 31),
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

/// Build a minimal unsigned JWT (header.payload.signature) for testing.
/// The signature is a dummy value since we only decode claims, not verify.
fn build_test_jwt(claims: &serde_json::Value) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"RS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signature = URL_SAFE_NO_PAD.encode(b"fake-signature");

    format!("{header}.{payload}.{signature}")
}
