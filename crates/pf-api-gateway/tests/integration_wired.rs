// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests with a mock `UserService` wired into the gateway.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-3 — Access Enforcement
//!
//! These tests exercise the full Axum router with a real JWT authentication
//! flow and a mock in-memory `UserService`, verifying end-to-end behavior
//! of the `/api/v1/users` routes.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use uuid::Uuid;

use pf_api_gateway::config::{GatewayConfig, JwtValidationConfig};
use pf_api_gateway::router::build_router;
use pf_api_gateway::server::AppState;
use pf_common::identity::{Edipi, Role};
use pf_common::job::CostCenter;
use pf_user_provisioning::{
    DefaultUserService, InMemoryUserRepository, ProvisionedUser, UserRepository, UserService,
    UserStatus,
};
use pf_user_provisioning::user::{ProvisioningSource, UserPreferences};

// ---------------------------------------------------------------------------
// JWT helpers (same pattern as integration_auth.rs)
// ---------------------------------------------------------------------------

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

/// Issue a test JWT with the given subject EDIPI, roles, and expiry offset.
fn issue_test_token(enc: &EncodingKey, sub: &str, roles: &[&str], exp_offset_secs: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub: sub.to_string(),
        iss: "printforge".to_string(),
        aud: "printforge-api".to_string(),
        exp: now + exp_offset_secs,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        scope: "session".to_string(),
        roles: roles.iter().copied().map(ToString::to_string).collect(),
    };

    let header = Header::new(Algorithm::EdDSA);
    encode(&header, &claims, enc).expect("sign token")
}

// ---------------------------------------------------------------------------
// Test user factory
// ---------------------------------------------------------------------------

fn make_test_user(edipi_str: &str, name: &str, org: &str) -> ProvisionedUser {
    let now = Utc::now();
    ProvisionedUser {
        id: Uuid::new_v4(),
        edipi: Edipi::new(edipi_str).unwrap(),
        display_name: name.to_string(),
        organization: org.to_string(),
        site_id: String::new(),
        roles: vec![Role::User],
        cost_centers: vec![CostCenter::new("CC001", "Test Center").unwrap()],
        preferences: UserPreferences::default(),
        status: UserStatus::Active,
        provisioning_source: ProvisioningSource::Jit,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    }
}

// ---------------------------------------------------------------------------
// State builders
// ---------------------------------------------------------------------------

/// Build a test `AppState` with a wired `UserService` and the given decoding key.
fn wired_test_state_with_key(
    user_svc: Option<Arc<dyn UserService>>,
    dec: DecodingKey,
) -> AppState {
    let config = GatewayConfig {
        jwt: JwtValidationConfig {
            issuer: "printforge".to_string(),
            audience: "printforge-api".to_string(),
            public_key_pem: String::new(),
        },
        ..GatewayConfig::default()
    };

    AppState {
        config: Arc::new(config),
        jwt_decoding_key: Some(Arc::new(dec)),
        user_service: user_svc,
        job_service: None,
        fleet_service: None,
        accounting_service: None,
        audit_service: None,
        alert_service: None,
        report_service: None,
        enroll: None,
    }
}

/// Create a `DefaultUserService` pre-populated with test users.
fn mock_user_service() -> Arc<dyn UserService> {
    let repo = InMemoryUserRepository::new();

    let alice = make_test_user("1234567890", "DOE.ALICE.A.1234567890", "Test Unit, Test Base AFB");
    let bob = make_test_user("0987654321", "DOE.BOB.B.0987654321", "Test Unit, Test Base AFB");
    let carol = make_test_user("1111111111", "DOE.CAROL.C.1111111111", "Test Unit 2, Test Base AFB");

    repo.create(&alice).unwrap();
    repo.create(&bob).unwrap();
    repo.create(&carol).unwrap();

    Arc::new(DefaultUserService::new(Box::new(repo)))
}

// ---------------------------------------------------------------------------
// Response deserialization types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ListUsersResp {
    users: Vec<UserSummaryResp>,
    total: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UserSummaryResp {
    edipi: String,
    name: String,
    org: String,
    roles: Vec<String>,
    suspended: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct UserDetailResp {
    edipi: String,
    name: String,
    org: String,
    roles: Vec<String>,
    suspended: bool,
    total_pages: u64,
    total_jobs: u64,
}

#[derive(Debug, Deserialize)]
struct UpdateRolesResp {
    edipi: String,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SuspendResp {
    edipi: String,
    suspended: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ErrorResp {
    request_id: String,
    status: u16,
    message: String,
}

// ---------------------------------------------------------------------------
// Helper: read response body as bytes
// ---------------------------------------------------------------------------

async fn body_bytes(resp: axum::http::Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

// ---------------------------------------------------------------------------
// Phase 7 — Integration tests with mock UserService
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wired_list_users_returns_preloaded_users() {
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body_bytes(resp).await;
    let list: ListUsersResp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(list.total, 3);
    assert_eq!(list.users.len(), 3);

    let edipis: Vec<&str> = list.users.iter().map(|u| u.edipi.as_str()).collect();
    assert!(edipis.contains(&"1234567890"));
    assert!(edipis.contains(&"0987654321"));
    assert!(edipis.contains(&"1111111111"));
}

#[tokio::test]
async fn wired_get_user_returns_specific_user() {
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state);

    // FleetAdmin viewing another user's profile.
    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users/0987654321")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body_bytes(resp).await;
    let detail: UserDetailResp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(detail.edipi, "0987654321");
    assert_eq!(detail.name, "DOE.BOB.B.0987654321");
}

#[tokio::test]
async fn wired_get_nonexistent_user_returns_404() {
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users/9999999999")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wired_update_roles_persists() {
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state.clone());

    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/users/0987654321/roles")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"roles": ["FleetAdmin", "User"]}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body_bytes(resp).await;
    let updated: UpdateRolesResp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(updated.edipi, "0987654321");
    assert!(updated.roles.contains(&"FleetAdmin".to_string()));
    assert!(updated.roles.contains(&"User".to_string()));
}

#[tokio::test]
async fn wired_suspend_user_succeeds() {
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/users/0987654321/suspend")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body_bytes(resp).await;
    let suspended: SuspendResp = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(suspended.edipi, "0987654321");
    assert!(suspended.suspended);
}

#[tokio::test]
async fn wired_user_route_returns_503_without_service() {
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(None, dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn nist_ac2_list_users_requires_admin() {
    // NIST 800-53 Rev 5: AC-2 — Account Management
    // Evidence: A user with only the User role cannot list all users.
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["User"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn nist_ac3_user_cannot_suspend_others() {
    // NIST 800-53 Rev 5: AC-3 — Access Enforcement
    // Evidence: A user with only the User role cannot suspend another user.
    let svc = mock_user_service();
    let (enc, dec, _) = generate_test_keys();
    let state = wired_test_state_with_key(Some(svc), dec);
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["User"], 3600);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/users/0987654321/suspend")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
