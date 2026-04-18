// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for JWT authentication and RBAC.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, IA-2 — Identification and Authentication

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use pf_api_gateway::config::{GatewayConfig, JwtValidationConfig};
use pf_api_gateway::router::build_router;
use pf_api_gateway::server::AppState;

/// JWT claims matching the `PrintForgeClaims` structure from pf-auth.
#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
    scope: String,
    roles: Vec<String>,
}

/// Generate an Ed25519 key pair and return the encoding key, decoding key, and public PEM.
fn generate_test_keys() -> (EncodingKey, DecodingKey, String) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pkcs8_bytes = pkcs8_doc.as_ref();

    let private_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        base64::engine::general_purpose::STANDARD.encode(pkcs8_bytes)
    );

    let kp = Ed25519KeyPair::from_pkcs8(pkcs8_bytes).expect("parse pkcs8");
    let public_key_bytes = kp.public_key().as_ref();

    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(public_key_bytes);

    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        base64::engine::general_purpose::STANDARD.encode(&spki)
    );

    let enc = EncodingKey::from_ed_pem(private_pem.as_bytes()).expect("encoding key");
    let dec = DecodingKey::from_ed_pem(public_pem.as_bytes()).expect("decoding key");

    (enc, dec, public_pem)
}

/// Build a test `AppState` with a valid JWT decoding key.
fn test_state_with_key(dec: DecodingKey) -> AppState {
    let config = GatewayConfig {
        jwt: JwtValidationConfig {
            issuer: "printforge".to_string(),
            audience: "printforge-api".to_string(),
            public_key_pem: String::new(), // Key is loaded directly
        },
        ..GatewayConfig::default()
    };

    AppState {
        config: Arc::new(config),
        jwt_decoding_key: Some(Arc::new(dec)),
        user_service: None,
        job_service: None,
        fleet_service: None,
        accounting_service: None,
        audit_service: None,
        alert_service: None,
    }
}

/// Issue a test JWT with the given roles and expiry.
fn issue_test_token(enc: &EncodingKey, roles: &[&str], exp_offset_secs: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub: "1234567890".to_string(),
        iss: "printforge".to_string(),
        aud: "printforge-api".to_string(),
        exp: now + exp_offset_secs,
        iat: now,
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: "session".to_string(),
        roles: roles.iter().copied().map(ToString::to_string).collect(),
    };

    let header = Header::new(Algorithm::EdDSA);
    encode(&header, &claims, enc).expect("sign token")
}

#[tokio::test]
async fn nist_ac3_valid_jwt_extracts_identity() {
    // NIST 800-53 Rev 5: AC-3, IA-2 — Valid JWT with correct signature
    // is accepted and the request reaches the route handler.
    let (enc, dec, _) = generate_test_keys();
    let state = test_state_with_key(dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, &["User"], 3600);
    let req = Request::builder()
        .uri("/api/v1/jobs")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // The route handler returns 200 (or whatever the stub returns).
    // The important thing is that it's NOT 401.
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nist_ac3_expired_jwt_returns_401() {
    // NIST 800-53 Rev 5: IA-5 — Expired tokens MUST be rejected.
    let (enc, dec, _) = generate_test_keys();
    let state = test_state_with_key(dec);
    let app = build_router(state);

    // Token expired 1 hour ago.
    let token = issue_test_token(&enc, &["User"], -3600);
    let req = Request::builder()
        .uri("/api/v1/jobs")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nist_ac3_missing_token_returns_401() {
    // NIST 800-53 Rev 5: AC-3 — Requests without authentication are rejected.
    let (_, dec, _) = generate_test_keys();
    let state = test_state_with_key(dec);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/jobs")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nist_ac3_invalid_signature_returns_401() {
    // NIST 800-53 Rev 5: IA-5 — Tokens signed with a different key are rejected.
    let (enc, _, _) = generate_test_keys();
    let (_, dec2, _) = generate_test_keys(); // Different key pair
    let state = test_state_with_key(dec2);
    let app = build_router(state);

    let token = issue_test_token(&enc, &["User"], 3600);
    let req = Request::builder()
        .uri("/api/v1/jobs")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nist_ac3_insufficient_role_returns_403() {
    // NIST 800-53 Rev 5: AC-3 — User role cannot access FleetAdmin routes.
    let (enc, dec, _) = generate_test_keys();
    let state = test_state_with_key(dec);
    let app = build_router(state);

    // User-only token trying to access /audit/events (requires Auditor)
    let token = issue_test_token(&enc, &["User"], 3600);
    let req = Request::builder()
        .uri("/api/v1/audit/events")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn nist_ac3_higher_role_grants_lower_access() {
    // NIST 800-53 Rev 5: AC-3 — FleetAdmin can access User-level routes.
    let (enc, dec, _) = generate_test_keys();
    let state = test_state_with_key(dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/jobs")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}
