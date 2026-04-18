// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Axum middleware functions attached at router construction time.
//!
//! These are thin wrappers around the token-bucket [`RateLimiter`] and
//! [`RequestAuditEntry`] types, which carry all the domain logic. The
//! middleware here is responsible for:
//!
//! - Extracting the client IP (respecting `X-Forwarded-For` from upstream
//!   proxies), feeding it into the per-IP rate limiter, and returning 429
//!   with a `Retry-After` header when the bucket is empty.
//! - Capturing request metadata, running the handler, then emitting a
//!   structured [`RequestAuditEntry`] on the response path.
//!
//! **NIST 800-53 Rev 5:** AC-17 (Remote Access), AU-2 / AU-3 / AU-12.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use uuid::Uuid;

use crate::middleware::audit::RequestAuditEntry;
use crate::middleware::rate_limit::{RateLimitResult, RateLimiter};

/// Shared handles for the token-bucket limiters, threaded into the rate
/// limit middleware as Axum state.
///
/// Only the per-IP bucket is consulted in middleware today. Per-user rate
/// limiting requires re-validating the JWT in middleware (which would
/// duplicate the extractor's work); it lives on the trait surface for
/// future wiring at the handler level.
#[derive(Debug, Clone)]
pub struct RateLimiters {
    /// Per-client-IP bucket. Cheap to clone (`Arc`).
    pub per_ip: Arc<RateLimiter>,
}

/// Axum middleware enforcing the per-IP rate limit.
///
/// Returns 429 Too Many Requests with a `Retry-After` seconds header when
/// the caller's bucket is empty. The handler chain is short-circuited in
/// that case — `next.run` is never called.
pub async fn rate_limit_mw(
    State(limiters): State<Arc<RateLimiters>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = extract_client_ip(req.headers());
    match limiters.per_ip.check_ip(ip) {
        RateLimitResult::Allowed => next.run(req).await,
        RateLimitResult::Limited { retry_after_secs } => {
            let mut response =
                (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
            if let Ok(hv) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, hv);
            }
            tracing::warn!(
                client_ip = %ip,
                retry_after_secs,
                "rate limit exceeded"
            );
            response
        }
    }
}

/// Axum middleware emitting a [`RequestAuditEntry`] on every response.
///
/// Runs outside-in: captures method/path/IP/user-agent before the handler,
/// runs the handler, then records status + duration on the way back out.
/// The entry's `actor` field is `None` today — extracting the EDIPI
/// without re-validating the JWT would require the extractor to stash it
/// in request extensions, a follow-up slice.
pub async fn audit_mw(req: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::now_v7);
    let source_ip = extract_client_ip(&headers);

    let response = next.run(req).await;

    let entry = RequestAuditEntry {
        request_id,
        timestamp: Utc::now(),
        actor: None,
        method: method.to_string(),
        path,
        source_ip,
        status_code: response.status().as_u16(),
        duration_ms: start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        user_agent,
    };
    entry.emit();

    response
}

/// Extract the client IP address from a request's headers.
///
/// Prefers the first entry of `X-Forwarded-For` (set by the upstream
/// load balancer / ingress), falls back to `0.0.0.0` when absent or
/// unparseable. This middleware layer MUST be downstream of a trusted
/// proxy in production — deployments that expose the gateway directly to
/// the internet would need a `ConnectInfo` extractor instead.
fn extract_client_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_client_ip_prefers_forwarded_for_first_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 10.0.0.1"),
        );
        let ip = extract_client_ip(&headers);
        assert_eq!(ip.to_string(), "203.0.113.5");
    }

    #[test]
    fn extract_client_ip_falls_back_to_unspecified() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn extract_client_ip_handles_malformed_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
}
