// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Authentication cache: cached OCSP responses and cert-to-EDIPI mappings.
//!
//! Provides offline authentication capability during `DDIL` mode by caching
//! previously validated certificate information with a configurable TTL
//! (default 4 hours).
//!
//! **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
//! Cached OCSP responses MUST be signature-validated before use.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use pf_common::identity::Edipi;
use serde::{Deserialize, Serialize};

use crate::config::AuthCacheConfig;
use crate::error::CacheNodeError;

/// A cached OCSP response with metadata for validation.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — cached OCSP responses must be
/// signature-validated before use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedOcspResponse {
    /// The certificate serial number this response applies to.
    pub cert_serial: String,
    /// Whether the certificate was reported as valid by OCSP.
    pub is_valid: bool,
    /// When the OCSP response was originally fetched.
    pub fetched_at: DateTime<Utc>,
    /// When this cache entry expires.
    pub expires_at: DateTime<Utc>,
    /// SHA-256 hash of the OCSP response for integrity verification.
    pub response_hash: String,
}

impl CachedOcspResponse {
    /// Check whether this cached response has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

/// A cached mapping from certificate fingerprint to EDIPI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEdipiMapping {
    /// SHA-256 fingerprint of the X.509 certificate.
    pub cert_fingerprint: String,
    /// The EDIPI extracted from the certificate Subject DN.
    pub edipi: Edipi,
    /// When this mapping was cached.
    pub cached_at: DateTime<Utc>,
    /// When this cache entry expires.
    pub expires_at: DateTime<Utc>,
}

impl CachedEdipiMapping {
    /// Check whether this cached mapping has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

/// Result of an auth cache lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup<T> {
    /// Cache hit: the entry is valid and not expired.
    Hit(T),
    /// Cache miss: no entry found.
    Miss,
    /// Cache entry found but expired.
    Expired,
}

/// In-memory authentication cache with configurable TTL and max entries.
///
/// **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
#[derive(Debug)]
pub struct AuthCache {
    /// TTL for cache entries.
    ttl: Duration,
    /// Maximum number of entries.
    max_entries: usize,
    /// OCSP response cache keyed by certificate serial number.
    ocsp_cache: HashMap<String, CachedOcspResponse>,
    /// EDIPI mapping cache keyed by certificate fingerprint.
    edipi_cache: HashMap<String, CachedEdipiMapping>,
    /// Running count of cache hits for metrics.
    hit_count: u64,
    /// Running count of cache misses for metrics.
    miss_count: u64,
}

impl AuthCache {
    /// Create a new `AuthCache` with the given configuration.
    #[must_use]
    pub fn new(config: &AuthCacheConfig) -> Self {
        Self {
            ttl: config.ttl,
            max_entries: config.max_entries,
            ocsp_cache: HashMap::new(),
            edipi_cache: HashMap::new(),
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Return the configured TTL.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Return the total number of entries across both caches.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.ocsp_cache.len() + self.edipi_cache.len()
    }

    /// Return the cache hit rate as a fraction (0.0 to 1.0).
    /// Returns 0.0 if no lookups have been performed.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hit_count + self.miss_count;
        if total == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.hit_count as f64 / total as f64
        }
    }

    /// Return the total number of cache hits.
    #[must_use]
    pub fn hit_count(&self) -> u64 {
        self.hit_count
    }

    /// Return the total number of cache misses.
    #[must_use]
    pub fn miss_count(&self) -> u64 {
        self.miss_count
    }

    /// Store a cached OCSP response.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::AuthCache` if the cache is full and
    /// eviction cannot free space (should not happen with current
    /// eviction strategy).
    pub fn store_ocsp(&mut self, response: CachedOcspResponse) -> Result<(), CacheNodeError> {
        self.evict_expired_ocsp();
        if self.ocsp_cache.len() >= self.max_entries {
            return Err(CacheNodeError::AuthCache {
                message: "OCSP cache at capacity".to_string(),
            });
        }
        tracing::debug!(
            cert_serial = %response.cert_serial,
            "caching OCSP response"
        );
        self.ocsp_cache
            .insert(response.cert_serial.clone(), response);
        Ok(())
    }

    /// Look up a cached OCSP response by certificate serial number.
    ///
    /// **NIST 800-53 Rev 5:** IA-5(2) — returns `Expired` if the
    /// cached response has exceeded its TTL.
    pub fn lookup_ocsp(&mut self, cert_serial: &str) -> CacheLookup<CachedOcspResponse> {
        match self.ocsp_cache.get(cert_serial) {
            Some(entry) if entry.is_expired() => {
                self.miss_count += 1;
                CacheLookup::Expired
            }
            Some(entry) => {
                self.hit_count += 1;
                CacheLookup::Hit(entry.clone())
            }
            None => {
                self.miss_count += 1;
                CacheLookup::Miss
            }
        }
    }

    /// Store a cached EDIPI mapping.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::AuthCache` if the cache is full.
    pub fn store_edipi(&mut self, mapping: CachedEdipiMapping) -> Result<(), CacheNodeError> {
        self.evict_expired_edipi();
        if self.edipi_cache.len() >= self.max_entries {
            return Err(CacheNodeError::AuthCache {
                message: "EDIPI cache at capacity".to_string(),
            });
        }
        tracing::debug!(
            cert_fingerprint = %mapping.cert_fingerprint,
            "caching EDIPI mapping"
        );
        self.edipi_cache
            .insert(mapping.cert_fingerprint.clone(), mapping);
        Ok(())
    }

    /// Look up a cached EDIPI mapping by certificate fingerprint.
    pub fn lookup_edipi(&mut self, cert_fingerprint: &str) -> CacheLookup<CachedEdipiMapping> {
        match self.edipi_cache.get(cert_fingerprint) {
            Some(entry) if entry.is_expired() => {
                self.miss_count += 1;
                CacheLookup::Expired
            }
            Some(entry) => {
                self.hit_count += 1;
                CacheLookup::Hit(entry.clone())
            }
            None => {
                self.miss_count += 1;
                CacheLookup::Miss
            }
        }
    }

    /// Remove all expired OCSP entries.
    pub fn evict_expired_ocsp(&mut self) {
        self.ocsp_cache.retain(|_, v| !v.is_expired());
    }

    /// Remove all expired EDIPI entries.
    pub fn evict_expired_edipi(&mut self) {
        self.edipi_cache.retain(|_, v| !v.is_expired());
    }

    /// Remove all entries from both caches.
    pub fn clear(&mut self) {
        self.ocsp_cache.clear();
        self.edipi_cache.clear();
        tracing::info!("auth cache cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuthCacheConfig {
        AuthCacheConfig {
            ttl: Duration::from_secs(3600),
            max_entries: 100,
        }
    }

    fn valid_ocsp_response() -> CachedOcspResponse {
        CachedOcspResponse {
            cert_serial: "ABC123".to_string(),
            is_valid: true,
            fetched_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(4),
            response_hash: "sha256:deadbeef".to_string(),
        }
    }

    fn expired_ocsp_response() -> CachedOcspResponse {
        CachedOcspResponse {
            cert_serial: "EXPIRED456".to_string(),
            is_valid: true,
            fetched_at: Utc::now() - chrono::Duration::hours(5),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            response_hash: "sha256:cafebabe".to_string(),
        }
    }

    fn valid_edipi_mapping() -> CachedEdipiMapping {
        CachedEdipiMapping {
            cert_fingerprint: "sha256:aabbccdd".to_string(),
            edipi: Edipi::new("1234567890").unwrap(),
            cached_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(4),
        }
    }

    #[test]
    fn nist_ia5_2_cache_hit_on_valid_ocsp() {
        let mut cache = AuthCache::new(&test_config());
        cache.store_ocsp(valid_ocsp_response()).unwrap();
        let result = cache.lookup_ocsp("ABC123");
        assert!(matches!(result, CacheLookup::Hit(_)));
    }

    #[test]
    fn nist_ia5_2_cache_miss_on_unknown_serial() {
        let mut cache = AuthCache::new(&test_config());
        let result = cache.lookup_ocsp("UNKNOWN");
        assert!(matches!(result, CacheLookup::Miss));
    }

    #[test]
    fn nist_ia5_2_expired_ocsp_returns_expired() {
        let mut cache = AuthCache::new(&test_config());
        cache.store_ocsp(expired_ocsp_response()).unwrap();
        let result = cache.lookup_ocsp("EXPIRED456");
        assert!(matches!(result, CacheLookup::Expired));
    }

    #[test]
    fn nist_ia5_2_edipi_cache_roundtrip() {
        let mut cache = AuthCache::new(&test_config());
        cache.store_edipi(valid_edipi_mapping()).unwrap();
        let result = cache.lookup_edipi("sha256:aabbccdd");
        assert!(matches!(result, CacheLookup::Hit(_)));
    }

    #[test]
    fn hit_rate_starts_at_zero() {
        let cache = AuthCache::new(&test_config());
        assert!((cache.hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hit_rate_updates_correctly() {
        let mut cache = AuthCache::new(&test_config());
        cache.store_ocsp(valid_ocsp_response()).unwrap();
        cache.lookup_ocsp("ABC123"); // hit
        cache.lookup_ocsp("MISSING"); // miss
        assert!((cache.hit_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut cache = AuthCache::new(&test_config());
        cache.store_ocsp(valid_ocsp_response()).unwrap();
        cache.store_edipi(valid_edipi_mapping()).unwrap();
        cache.clear();
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn default_auth_cache_ttl_is_four_hours() {
        let config = AuthCacheConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(4 * 3600));
    }
}
