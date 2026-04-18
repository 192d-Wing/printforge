// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Token-bucket rate limiter per client IP and per authenticated user.
//!
//! Returns HTTP 429 with a `Retry-After` header when the rate limit
//! is exceeded.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::config::RateLimitConfig;

/// A token-bucket rate limiter that tracks per-key request rates.
///
/// Thread-safe via internal `Mutex`. Designed for moderate cardinality
/// (thousands of IPs / users, not millions).
#[derive(Debug)]
pub struct RateLimiter {
    config: BucketConfig,
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

/// Configuration for a single bucket tier (per-IP or per-user).
#[derive(Debug, Clone, Copy)]
pub struct BucketConfig {
    /// Tokens added per second.
    pub refill_rate: u32,
    /// Maximum tokens the bucket can hold.
    pub burst: u32,
}

/// A single token bucket.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    burst: u32,
    refill_rate: u32,
}

impl TokenBucket {
    fn new(config: BucketConfig) -> Self {
        Self {
            tokens: f64::from(config.burst),
            last_refill: Instant::now(),
            burst: config.burst,
            refill_rate: config.refill_rate,
        }
    }

    /// Try to consume one token. Returns `true` if allowed, `false` if rate limited.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Estimated seconds until a token is available.
    fn retry_after_secs(&self) -> u64 {
        if self.refill_rate == 0 {
            return 60;
        }
        let deficit = 1.0 - self.tokens;
        if deficit <= 0.0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let secs = (deficit / f64::from(self.refill_rate)).ceil() as u64;
        secs
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * f64::from(self.refill_rate)).min(f64::from(self.burst));
        self.last_refill = now;
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed,
    /// Request is denied; retry after the given number of seconds.
    Limited { retry_after_secs: u64 },
}

impl RateLimiter {
    /// Create a new rate limiter with the given bucket configuration.
    #[must_use]
    pub fn new(config: BucketConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Create a per-IP rate limiter from the gateway rate limit config.
    #[must_use]
    pub fn per_ip(config: &RateLimitConfig) -> Self {
        Self::new(BucketConfig {
            refill_rate: config.per_ip_rps,
            burst: config.per_ip_burst,
        })
    }

    /// Create a per-user rate limiter from the gateway rate limit config.
    #[must_use]
    pub fn per_user(config: &RateLimitConfig) -> Self {
        Self::new(BucketConfig {
            refill_rate: config.per_user_rps,
            burst: config.per_user_burst,
        })
    }

    /// Check whether a request from the given key is allowed.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn check(&self, key: &str) -> RateLimitResult {
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config));

        if bucket.try_consume() {
            RateLimitResult::Allowed
        } else {
            RateLimitResult::Limited {
                retry_after_secs: bucket.retry_after_secs(),
            }
        }
    }

    /// Check a request by client IP address.
    pub fn check_ip(&self, ip: IpAddr) -> RateLimitResult {
        self.check(&ip.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BucketConfig {
        BucketConfig {
            refill_rate: 10,
            burst: 5,
        }
    }

    #[test]
    fn allows_requests_within_burst() {
        let limiter = RateLimiter::new(test_config());
        for _ in 0..5 {
            assert_eq!(limiter.check("test-key"), RateLimitResult::Allowed);
        }
    }

    #[test]
    fn denies_requests_exceeding_burst() {
        let limiter = RateLimiter::new(test_config());
        // Exhaust the burst.
        for _ in 0..5 {
            let _ = limiter.check("test-key");
        }
        // Next request should be limited.
        let result = limiter.check("test-key");
        assert!(matches!(result, RateLimitResult::Limited { .. }));
    }

    #[test]
    fn separate_keys_have_separate_buckets() {
        let limiter = RateLimiter::new(test_config());
        // Exhaust one key's burst.
        for _ in 0..5 {
            let _ = limiter.check("key-a");
        }
        // Different key should still be allowed.
        assert_eq!(limiter.check("key-b"), RateLimitResult::Allowed);
    }

    #[test]
    fn check_ip_delegates_correctly() {
        let limiter = RateLimiter::new(test_config());
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(limiter.check_ip(ip), RateLimitResult::Allowed);
    }

    #[test]
    fn per_ip_constructor() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::per_ip(&config);
        assert_eq!(limiter.check("1.2.3.4"), RateLimitResult::Allowed);
    }

    #[test]
    fn per_user_constructor() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::per_user(&config);
        assert_eq!(limiter.check("1234567890"), RateLimitResult::Allowed);
    }

    #[test]
    fn limited_result_has_positive_retry_after() {
        let limiter = RateLimiter::new(BucketConfig {
            refill_rate: 1,
            burst: 1,
        });
        let _ = limiter.check("k");
        if let RateLimitResult::Limited { retry_after_secs } = limiter.check("k") {
            assert!(retry_after_secs >= 1);
        } else {
            panic!("expected Limited result");
        }
    }
}
