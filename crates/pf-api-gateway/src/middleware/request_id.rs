// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! X-Request-ID injection for distributed tracing.
//!
//! Ensures every request has a unique identifier for log correlation.
//! If the incoming request already contains an `X-Request-ID` header
//! (e.g., from a load balancer), it is preserved. Otherwise a new
//! `UUIDv4` is generated.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::{HeaderValue, Request};
use tower::{Layer, Service};
use uuid::Uuid;

/// Header name for the request identifier.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Tower layer that injects an `X-Request-ID` header into every request
/// and copies it to the response.
#[derive(Debug, Clone, Copy)]
pub struct RequestIdLayer;

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService { inner }
    }
}

/// Tower service that injects `X-Request-ID`.
#[derive(Debug, Clone)]
pub struct RequestIdService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for RequestIdService<S>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Response: Send,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // Preserve existing request ID or generate a new one.
        if !req.headers().contains_key(REQUEST_ID_HEADER) {
            let id = Uuid::new_v4().to_string();
            if let Ok(val) = HeaderValue::from_str(&id) {
                req.headers_mut().insert(REQUEST_ID_HEADER, val);
            }
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

/// Extract the request ID from a request's headers, returning the parsed
/// `Uuid` if present and valid.
///
/// # Errors
///
/// Returns `None` if the header is absent or not a valid UUID.
pub fn extract_request_id<B>(req: &Request<B>) -> Option<Uuid> {
    req.headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;

    use super::*;

    #[test]
    fn extract_request_id_parses_valid_uuid() {
        let id = Uuid::new_v4();
        let req = Request::builder()
            .header(REQUEST_ID_HEADER, id.to_string())
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_request_id(&req), Some(id));
    }

    #[test]
    fn extract_request_id_returns_none_when_missing() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_request_id(&req), None);
    }

    #[test]
    fn extract_request_id_returns_none_for_invalid() {
        let req = Request::builder()
            .header(REQUEST_ID_HEADER, "not-a-uuid")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_request_id(&req), None);
    }
}
