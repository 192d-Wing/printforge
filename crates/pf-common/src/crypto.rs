// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 `PrintForge` Contributors

//! FIPS-safe cryptographic wrappers using `ring`.
//!
//! **NIST 800-53 Rev 5:** SC-13 — Cryptographic Protection
//!
//! All cryptographic operations in `PrintForge` MUST go through this module.
//! Direct use of other crypto crates is prohibited.
//! `ring` is derived from `BoringSSL` (FIPS 140-3 validated).

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::CommonError;

/// Cryptographically-secure random number generator.
///
/// Uses `ring::rand::SystemRandom` (backed by the OS CSPRNG).
/// **NEVER** use `rand` crate for security-critical randomness.
fn system_rng() -> &'static SystemRandom {
    use std::sync::LazyLock;
    static RNG: LazyLock<SystemRandom> = LazyLock::new(SystemRandom::new);
    &RNG
}

/// Generate `len` bytes of cryptographically-secure random data.
///
/// # Errors
///
/// Returns `CommonError::Crypto` if the system RNG fails.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CommonError> {
    let mut buf = vec![0u8; len];
    system_rng()
        .fill(&mut buf)
        .map_err(|_| CommonError::Crypto {
            message: "failed to generate random bytes".to_string(),
        })?;
    Ok(buf)
}

/// Compute the SHA-256 digest of the given data.
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// Compute the SHA-256 digest and return it as a hex string.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_sc13_random_bytes_returns_requested_length() {
        let bytes = random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn nist_sc13_random_bytes_are_not_all_zero() {
        let bytes = random_bytes(32).unwrap();
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
