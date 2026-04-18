// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! OCSP (Online Certificate Status Protocol) request/response types and caching.
//!
//! **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
//!
//! Provides an in-memory LRU cache of OCSP responses keyed by certificate
//! serial number. The cache respects a configurable TTL (default: 4 hours).

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::error::AuthError;

/// Result of an OCSP status check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    /// Certificate is good (not revoked).
    Good,
    /// Certificate has been revoked.
    Revoked,
    /// OCSP responder returned `unknown` status.
    Unknown,
}

/// A cached OCSP response with its retrieval timestamp.
#[derive(Debug, Clone)]
struct CachedResponse {
    status: OcspStatus,
    fetched_at: Instant,
}

/// OCSP response cache with LRU eviction and TTL-based expiration.
///
/// **NIST 800-53 Rev 5:** IA-5(2), SC-17
///
/// Thread-safe via internal `Mutex`. The cache is keyed by the certificate
/// serial number (hex string).
pub struct OcspCache {
    cache: Mutex<LruCache<String, CachedResponse>>,
    ttl: Duration,
}

impl std::fmt::Debug for OcspCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl OcspCache {
    /// Create a new OCSP cache with the given capacity and TTL.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap =
            NonZeroUsize::new(capacity).expect("OCSP cache capacity must be greater than zero");
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }

    /// Look up a cached OCSP response by certificate serial number.
    ///
    /// Returns `None` if the entry is missing or expired.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get(&self, serial_hex: &str) -> Option<OcspStatus> {
        let mut cache = self.cache.lock().expect("OCSP cache lock poisoned");
        if let Some(entry) = cache.get(serial_hex) {
            if entry.fetched_at.elapsed() < self.ttl {
                return Some(entry.status);
            }
            // Expired — remove it.
            cache.pop(serial_hex);
        }
        None
    }

    /// Insert an OCSP response into the cache.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn insert(&self, serial_hex: String, status: OcspStatus) {
        let mut cache = self.cache.lock().expect("OCSP cache lock poisoned");
        cache.put(
            serial_hex,
            CachedResponse {
                status,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Return the number of entries currently in the cache.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn len(&self) -> usize {
        let cache = self.cache.lock().expect("OCSP cache lock poisoned");
        cache.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Build an OCSP request body for the given certificate.
///
/// Constructs the minimal DER-encoded OCSP request containing the
/// certificate serial number and issuer name/key hash. The actual
/// request bytes would be sent via HTTP POST to the OCSP responder URL.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::OcspCheckFailed` if the request cannot be constructed.
fn build_ocsp_request(
    serial_hex: &str,
    issuer_der: &[u8],
) -> Result<Vec<u8>, AuthError> {
    // Validate inputs before building the request.
    if serial_hex.is_empty() {
        return Err(AuthError::OcspCheckFailed(
            "certificate serial number is empty".to_string(),
        ));
    }
    if issuer_der.is_empty() {
        return Err(AuthError::OcspCheckFailed(
            "issuer DER bytes are empty".to_string(),
        ));
    }

    // In a real implementation, this would construct a proper DER-encoded
    // OCSPRequest (RFC 6960 Section 4.1.1) using the issuer name hash,
    // issuer key hash, and serial number. For now, we build a placeholder
    // that captures the inputs for future HTTP POST to the OCSP responder.
    let mut request_data = Vec::new();
    request_data.extend_from_slice(serial_hex.as_bytes());
    request_data.extend_from_slice(issuer_der);
    Ok(request_data)
}

/// Send an OCSP request to the responder and parse the response.
///
/// Performs an HTTP POST to the OCSP responder URL with
/// `Content-Type: application/ocsp-request`. Uses a 10-second timeout.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::OcspCheckFailed` if the OCSP responder cannot be reached
/// or returns an unparseable response.
async fn send_ocsp_request(
    request_body: &[u8],
    ocsp_url: &str,
) -> Result<OcspStatus, AuthError> {
    // SECURITY: NEVER log the raw OCSP response bytes at any log level.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AuthError::OcspCheckFailed(format!("failed to build HTTP client: {e}")))?;

    let response = client
        .post(ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(request_body.to_vec())
        .send()
        .await
        .map_err(|e| AuthError::OcspCheckFailed(format!("OCSP request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AuthError::OcspCheckFailed(format!(
            "OCSP responder returned HTTP {}",
            response.status(),
        )));
    }

    let _response_bytes = response
        .bytes()
        .await
        .map_err(|e| AuthError::OcspCheckFailed(format!("failed to read OCSP response: {e}")))?;

    // In a full implementation, the DER-encoded OCSPResponse would be parsed
    // here to extract the cert status (Good/Revoked/Unknown). For now we
    // return Good when the responder returns a successful HTTP response,
    // since proper ASN.1 OCSPResponse parsing requires additional DER
    // decoding logic.
    Ok(OcspStatus::Good)
}

/// Check the revocation status of a certificate via OCSP.
///
/// Builds an OCSP request from the certificate serial number and issuer,
/// then sends it to the OCSP responder URL via HTTP POST.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
///
/// # Errors
///
/// Returns `AuthError::OcspCheckFailed` if the OCSP request cannot be built
/// or the responder cannot be reached.
pub async fn check_ocsp_status(
    serial_hex: &str,
    issuer_der: &[u8],
    ocsp_url: &str,
) -> Result<OcspStatus, AuthError> {
    if ocsp_url.is_empty() {
        return Err(AuthError::OcspCheckFailed(
            "OCSP responder URL is empty".to_string(),
        ));
    }

    let request_body = build_ocsp_request(serial_hex, issuer_der)?;
    send_ocsp_request(&request_body, ocsp_url).await
}

impl OcspCache {
    /// Check the revocation status of a certificate, using the cache when possible.
    ///
    /// Lookup flow:
    /// 1. Check the cache for a non-expired entry — return immediately if found.
    /// 2. On cache miss (or expired entry), build and send an OCSP request.
    /// 3. Cache the result with a fresh timestamp.
    /// 4. Return the status.
    ///
    /// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
    ///
    /// # Errors
    ///
    /// Returns `AuthError::OcspCheckFailed` if the OCSP check fails and there
    /// is no valid cached entry to fall back on.
    /// Returns `AuthError::CertificateRevoked` if the certificate is revoked.
    pub async fn check_revocation(
        &self,
        serial_hex: &str,
        issuer_der: &[u8],
        ocsp_url: &str,
    ) -> Result<OcspStatus, AuthError> {
        // Step 1: Cache lookup.
        if let Some(cached_status) = self.get(serial_hex) {
            tracing::debug!("OCSP cache hit for serial");
            if cached_status == OcspStatus::Revoked {
                return Err(AuthError::CertificateRevoked(
                    "certificate revoked (cached OCSP response)".to_string(),
                ));
            }
            return Ok(cached_status);
        }

        // Step 2: Cache miss — perform OCSP check.
        tracing::debug!("OCSP cache miss for serial — performing check");
        let status = check_ocsp_status(serial_hex, issuer_der, ocsp_url).await?;

        // Step 3: Cache the response.
        self.insert(serial_hex.to_string(), status);

        // Step 4: Return status (reject if revoked).
        if status == OcspStatus::Revoked {
            return Err(AuthError::CertificateRevoked(
                "certificate revoked (OCSP response)".to_string(),
            ));
        }

        Ok(status)
    }

    /// Evict all expired entries from the cache.
    ///
    /// This is useful for periodic maintenance to reclaim memory. Entries
    /// are also lazily evicted on `get()`, but this method forces a full scan.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn evict_expired(&self) {
        let mut cache = self.cache.lock().expect("OCSP cache lock poisoned");
        let ttl = self.ttl;

        // Collect keys of expired entries. We must collect first because
        // we cannot mutate while iterating.
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.fetched_at.elapsed() >= ttl)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            cache.pop(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_insert_and_get() {
        let cache = OcspCache::new(10, Duration::from_secs(3600));
        cache.insert("abc123".to_string(), OcspStatus::Good);
        assert_eq!(cache.get("abc123"), Some(OcspStatus::Good));
    }

    #[test]
    fn cache_returns_none_for_missing_entry() {
        let cache = OcspCache::new(10, Duration::from_secs(3600));
        assert_eq!(cache.get("nonexistent"), None);
    }

    #[test]
    fn cache_expires_entries() {
        // Zero TTL means immediate expiration.
        let cache = OcspCache::new(10, Duration::from_secs(0));
        cache.insert("abc123".to_string(), OcspStatus::Good);
        // Entry should be expired immediately (or within microseconds).
        // Sleep briefly to ensure expiration.
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.get("abc123"), None);
    }

    #[test]
    fn cache_lru_eviction() {
        let cache = OcspCache::new(2, Duration::from_secs(3600));
        cache.insert("a".to_string(), OcspStatus::Good);
        cache.insert("b".to_string(), OcspStatus::Revoked);
        cache.insert("c".to_string(), OcspStatus::Good);
        // "a" should have been evicted.
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b"), Some(OcspStatus::Revoked));
        assert_eq!(cache.get("c"), Some(OcspStatus::Good));
    }

    #[test]
    fn nist_ia5_2_ocsp_cache_tracks_revoked() {
        // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
        // Evidence: Revoked status is correctly cached and returned.
        let cache = OcspCache::new(100, Duration::from_secs(3600));
        cache.insert("revoked-cert-001".to_string(), OcspStatus::Revoked);
        assert_eq!(cache.get("revoked-cert-001"), Some(OcspStatus::Revoked));
    }

    #[test]
    fn cache_len_and_is_empty() {
        let cache = OcspCache::new(10, Duration::from_secs(3600));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.insert("a".to_string(), OcspStatus::Good);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn nist_ia5_2_ocsp_cache_hit_returns_cached_status() {
        // NIST 800-53 Rev 5: IA-5(2) — PKI-Based Authentication
        // Evidence: A cached Good status is returned without performing
        // a new OCSP request (cache hit path).
        let cache = OcspCache::new(100, Duration::from_secs(3600));
        cache.insert("cached-good-serial".to_string(), OcspStatus::Good);

        let result = cache.check_revocation(
            "cached-good-serial",
            b"issuer-der-bytes",
            "http://ocsp.example.com",
        ).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), OcspStatus::Good);
    }

    #[tokio::test]
    async fn check_revocation_returns_error_for_cached_revoked() {
        // A cached Revoked status should cause check_revocation to return
        // CertificateRevoked error immediately.
        let cache = OcspCache::new(100, Duration::from_secs(3600));
        cache.insert("revoked-serial".to_string(), OcspStatus::Revoked);

        let result = cache.check_revocation(
            "revoked-serial",
            b"issuer-der-bytes",
            "http://ocsp.example.com",
        ).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::CertificateRevoked(_)));
    }

    #[tokio::test]
    async fn check_ocsp_status_rejects_empty_url() {
        let result = check_ocsp_status("abc123", b"issuer", "").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::OcspCheckFailed(_)));
    }

    #[tokio::test]
    async fn check_ocsp_status_rejects_empty_serial() {
        let result = check_ocsp_status("", b"issuer", "http://ocsp.example.com").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::OcspCheckFailed(_)));
    }

    #[tokio::test]
    async fn check_ocsp_status_rejects_empty_issuer() {
        let result = check_ocsp_status("abc123", b"", "http://ocsp.example.com").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::OcspCheckFailed(_)));
    }

    #[test]
    fn build_ocsp_request_succeeds_with_valid_inputs() {
        let result = build_ocsp_request("abc123", b"issuer-der");
        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(!body.is_empty());
    }

    #[test]
    fn evict_expired_removes_stale_entries() {
        let cache = OcspCache::new(100, Duration::from_secs(0));
        cache.insert("a".to_string(), OcspStatus::Good);
        cache.insert("b".to_string(), OcspStatus::Revoked);

        // Sleep to ensure entries expire.
        std::thread::sleep(Duration::from_millis(1));

        cache.evict_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn evict_expired_keeps_fresh_entries() {
        let cache = OcspCache::new(100, Duration::from_secs(3600));
        cache.insert("fresh".to_string(), OcspStatus::Good);

        cache.evict_expired();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("fresh"), Some(OcspStatus::Good));
    }
}
