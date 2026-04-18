// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! End-to-end integration tests against real `PostgreSQL` and wired services.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-3 — Access Enforcement
//!
//! These tests exercise the full Axum router with a real `PgUserRepository`
//! backed by a live `PostgreSQL` database. All tests are `#[ignore = "requires running PostgreSQL — set PF_E2E_ENABLED=1"]` by default
//! and only run when `PF_E2E_ENABLED=1` is set in the environment:
//!
//! ```bash
//! PF_E2E_ENABLED=1 cargo nextest run -p pf-api-gateway --run-ignored all
//! ```
//!
//! **Prerequisites:**
//! - `PostgreSQL` running on `localhost:5432` (user: `printforge`, db: `printforge`)
//! - Test users seeded in the `users` table

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use ring::signature::{Ed25519KeyPair, KeyPair};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use uuid::Uuid;

use pf_api_gateway::config::{GatewayConfig, JwtValidationConfig};
use pf_api_gateway::router::build_router;
use pf_api_gateway::server::AppState;
use pf_common::config::DatabaseConfig;
use pf_user_provisioning::pg_repo::PgUserRepository;
use pf_user_provisioning::{DefaultUserService, UserService};

// ---------------------------------------------------------------------------
// Guard: skip tests when infrastructure is not available
// ---------------------------------------------------------------------------

/// Returns `true` if `PF_E2E_ENABLED` is set to `"1"`.
fn e2e_enabled() -> bool {
    std::env::var("PF_E2E_ENABLED")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/// Create a `DatabaseConfig` pointing at the local dev `PostgreSQL`.
fn dev_database_config() -> DatabaseConfig {
    DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        database: "printforge".to_string(),
        username: "printforge".to_string(),
        password: Some(SecretString::from("printforge-dev-only".to_string())),
        max_connections: 5,
        tls: None,
    }
}

/// Create a connection pool to the dev database.
async fn dev_pool() -> sqlx::PgPool {
    let cfg = dev_database_config();
    pf_common::database::create_pool(&cfg)
        .await
        .expect("failed to connect to dev PostgreSQL — is it running on localhost:5432?")
}

// ---------------------------------------------------------------------------
// JWT helpers (local Ed25519 key pair, same pattern as integration_wired.rs)
// ---------------------------------------------------------------------------

/// JWT claims matching the `PrintForgeClaims` structure expected by the gateway.
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

/// Generate an Ed25519 key pair and return (`encoding_key`, `decoding_key`, `public_pem`).
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

    // Wrap the raw Ed25519 public key in SPKI DER encoding.
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

/// Issue a test JWT with the given subject EDIPI and roles.
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
// AppState builder with real services
// ---------------------------------------------------------------------------

/// Build an `AppState` wired to real `PostgreSQL` via `PgUserRepository`.
async fn live_app_state(dec: DecodingKey) -> AppState {
    let pool = dev_pool().await;

    let repo = PgUserRepository::new(pool);
    let user_svc: Arc<dyn UserService> =
        Arc::new(DefaultUserService::new(Box::new(repo)));

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
        user_service: Some(user_svc),
        job_service: None,
        fleet_service: None,
        accounting_service: None,
        audit_service: None,
    }
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
    roles: Vec<serde_json::Value>,
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

/// Read the full response body as bytes.
async fn body_bytes(resp: axum::http::Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

// ---------------------------------------------------------------------------
// End-to-end tests — all #[ignore = "requires running PostgreSQL — set PF_E2E_ENABLED=1"] by default
// ---------------------------------------------------------------------------

/// Verify that GET /api/v1/users returns the seeded users from the real database.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
/// Evidence: The user provisioning service reads from a real `PostgreSQL` users table.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running PostgreSQL — set PF_E2E_ENABLED=1"]
async fn e2e_list_users_from_database() {
    if !e2e_enabled() {
        eprintln!("skipping e2e test: PF_E2E_ENABLED is not set to 1");
        return;
    }

    let (enc, dec, _) = generate_test_keys();
    let state = live_app_state(dec).await;
    let app = build_router(state);

    // Issue a FleetAdmin JWT to authorize the list-users call.
    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    if status != StatusCode::OK {
        eprintln!("Response body: {}", String::from_utf8_lossy(&bytes));
    }
    assert_eq!(status, StatusCode::OK, "expected 200 from /api/v1/users");

    let list: ListUsersResp = serde_json::from_slice(&bytes)
        .expect("failed to deserialize ListUsersResp");

    // The dev environment seeds 3 test users.
    assert!(
        list.total >= 3,
        "expected at least 3 seeded users, got {}",
        list.total
    );

    let edipis: Vec<&str> = list.users.iter().map(|u| u.edipi.as_str()).collect();
    assert!(
        edipis.contains(&"1234567890"),
        "seeded user DOE.JOHN.Q.1234567890 not found in response"
    );
    assert!(
        edipis.contains(&"0987654321"),
        "seeded user SMITH.JANE.A.0987654321 not found in response"
    );
    assert!(
        edipis.contains(&"1111111111"),
        "seeded user ADMIN.FLEET.X.1111111111 not found in response"
    );
}

/// Verify that GET /api/v1/users/:edipi returns the correct user details.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
/// Evidence: Individual user lookup by EDIPI works against a real database.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running PostgreSQL — set PF_E2E_ENABLED=1"]
async fn e2e_get_user_by_edipi() {
    if !e2e_enabled() {
        eprintln!("skipping e2e test: PF_E2E_ENABLED is not set to 1");
        return;
    }

    let (enc, dec, _) = generate_test_keys();
    let state = live_app_state(dec).await;
    let app = build_router(state);

    let token = issue_test_token(&enc, "1234567890", &["FleetAdmin"], 3600);
    let req = Request::builder()
        .uri("/api/v1/users/1234567890")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "expected 200 from /api/v1/users/1234567890");

    let bytes = body_bytes(resp).await;
    let detail: UserDetailResp = serde_json::from_slice(&bytes)
        .expect("failed to deserialize UserDetailResp");

    assert_eq!(detail.edipi, "1234567890");
    // The seeded user's display name should contain "DOE" (DOE.JOHN.Q.1234567890).
    assert!(
        detail.name.contains("DOE"),
        "expected display name to contain 'DOE', got '{}'",
        detail.name
    );
}

/// Verify that health and readiness endpoints work with real services wired.
///
/// When a `user_service` is present, `/readyz` should return `"ready"` (not
/// `"ready (no backends)"`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires running PostgreSQL — set PF_E2E_ENABLED=1"]
async fn e2e_health_check_with_services() {
    if !e2e_enabled() {
        eprintln!("skipping e2e test: PF_E2E_ENABLED is not set to 1");
        return;
    }

    let (_enc, dec, _) = generate_test_keys();
    let state = live_app_state(dec).await;
    let app = build_router(state);

    // --- /healthz ---
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "/healthz should return 200");

    // --- /readyz ---
    let req = Request::builder()
        .uri("/readyz")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "/readyz should return 200");

    let bytes = body_bytes(resp).await;
    let text = String::from_utf8(bytes).expect("readyz body should be UTF-8");
    assert!(
        text.contains("ready"),
        "expected readyz body to contain 'ready', got '{text}'"
    );
    assert!(
        !text.contains("no backends"),
        "readyz should NOT report 'no backends' when user_service is wired, got '{text}'"
    );
}
