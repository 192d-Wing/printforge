// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for the `pf-spool` crate.
//!
//! These tests exercise the encryption, key management, retention, and
//! configuration modules through their public APIs, providing compliance
//! evidence for NIST 800-53 Rev 5 controls SC-28, SC-12, and SC-13.

use std::time::Duration;

use chrono::{TimeDelta, Utc};

use pf_spool::config::{KeyStoreConfig, RetentionConfig, SpoolConfig};
use pf_spool::encryption::{self, Dek, EncryptedPayload, WrappedDek};
use pf_spool::error::SpoolError;
use pf_spool::key_store::{InMemoryKeyStore, KeyStore};
use pf_spool::retention::{self, RetentionPolicy};

// ---------------------------------------------------------------------------
// Encryption round-trip tests (NIST SC-28)
// ---------------------------------------------------------------------------

#[test]
fn nist_sc28_encrypt_decrypt_round_trip() {
    // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
    // Evidence: Plaintext survives an encrypt-then-decrypt round trip through
    // the public API. Verifies both small and large payloads.
    let dek = Dek::generate().expect("DEK generation must succeed");

    let payloads: &[&[u8]] = &[
        b"Short spool payload",
        &vec![0xAB_u8; 64 * 1024], // 64 KiB simulated PDF
        b"",                        // empty payload edge case
    ];

    for plaintext in payloads {
        let encrypted = encryption::encrypt(&dek, plaintext)
            .expect("encryption must succeed");
        let decrypted = encryption::decrypt(&dek, &encrypted)
            .expect("decryption must succeed");
        assert_eq!(
            &decrypted, plaintext,
            "round-trip failed for payload of length {}",
            plaintext.len()
        );
    }
}

#[test]
fn nist_sc28_different_deks_produce_different_ciphertext() {
    // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
    // Evidence: Encrypting the same plaintext with two different DEKs
    // produces distinct ciphertext, demonstrating per-job key isolation.
    let dek1 = Dek::generate().expect("DEK generation must succeed");
    let dek2 = Dek::generate().expect("DEK generation must succeed");
    let plaintext = b"Identical spool data for two different print jobs";

    let enc1 = encryption::encrypt(&dek1, plaintext).expect("encrypt with dek1");
    let enc2 = encryption::encrypt(&dek2, plaintext).expect("encrypt with dek2");

    // With different keys AND different random nonces, the ciphertext must differ.
    assert_ne!(
        enc1.ciphertext, enc2.ciphertext,
        "ciphertext must differ when encrypted with different DEKs"
    );
}

#[test]
fn nist_sc28_tampered_ciphertext_fails_decryption() {
    // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
    // Evidence: Flipping a single byte in the ciphertext causes the GCM
    // authentication tag to fail, resulting in IntegrityFailure.
    let dek = Dek::generate().expect("DEK generation must succeed");
    let plaintext = b"Print job that must not be tampered with";

    let mut encrypted = encryption::encrypt(&dek, plaintext).expect("encryption");

    // Tamper with a byte in the middle of the ciphertext.
    let mid = encrypted.ciphertext.len() / 2;
    encrypted.ciphertext[mid] ^= 0xFF;

    let result = encryption::decrypt(&dek, &encrypted);
    assert!(
        matches!(result, Err(SpoolError::IntegrityFailure)),
        "tampered ciphertext must be detected: got {result:?}"
    );
}

#[test]
fn nist_sc28_wrong_dek_fails_decryption() {
    // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
    // Evidence: Decrypting with a different DEK fails, preventing
    // cross-job data leakage.
    let dek_encrypt = Dek::generate().expect("DEK generation");
    let dek_wrong = Dek::generate().expect("DEK generation");
    let plaintext = b"Confidential spool data for USAF print job";

    let encrypted = encryption::encrypt(&dek_encrypt, plaintext).expect("encryption");

    let result = encryption::decrypt(&dek_wrong, &encrypted);
    assert!(
        matches!(result, Err(SpoolError::IntegrityFailure)),
        "wrong DEK must cause IntegrityFailure: got {result:?}"
    );
}

#[test]
fn nist_sc28_tampered_nonce_fails_decryption() {
    // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
    // Evidence: Modifying the nonce causes decryption failure.
    let dek = Dek::generate().expect("DEK generation");
    let plaintext = b"Nonce integrity matters";

    let mut encrypted = encryption::encrypt(&dek, plaintext).expect("encryption");
    encrypted.nonce[0] ^= 0xFF;

    let result = encryption::decrypt(&dek, &encrypted);
    assert!(
        result.is_err(),
        "tampered nonce must cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// Key management tests (NIST SC-12)
// ---------------------------------------------------------------------------

#[test]
fn nist_sc12_dek_generation_produces_unique_keys() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: 100 generated DEKs are all distinct, demonstrating the
    // randomness source produces unique keys.
    let deks: Vec<Dek> = (0..100)
        .map(|_| Dek::generate().expect("DEK generation"))
        .collect();

    for (i, a) in deks.iter().enumerate() {
        for b in &deks[i + 1..] {
            assert_ne!(
                a.as_bytes(),
                b.as_bytes(),
                "two generated DEKs must never be identical"
            );
        }
    }
}

#[test]
fn nist_sc12_kek_wrapping_round_trip() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: A DEK wrapped with a KEK can be unwrapped to recover the
    // original key material, proving the wrap/unwrap cycle is lossless.
    let kek = pf_common::crypto::random_bytes(32).expect("KEK generation");
    let dek = Dek::generate().expect("DEK generation");
    let original_bytes = dek.as_bytes().to_vec();

    let wrapped = encryption::wrap_dek(&kek, "integration-kek-001", &dek)
        .expect("wrap must succeed");

    // The wrapped payload must not contain the plaintext DEK.
    assert_ne!(
        &wrapped.payload.ciphertext[..32.min(wrapped.payload.ciphertext.len())],
        &original_bytes[..32.min(original_bytes.len())],
        "wrapped DEK must not contain plaintext key material"
    );

    let unwrapped = encryption::unwrap_dek(&kek, &wrapped).expect("unwrap must succeed");
    assert_eq!(
        unwrapped.as_bytes(),
        &original_bytes,
        "unwrapped DEK must match original"
    );
}

#[test]
fn nist_sc12_wrong_kek_fails_unwrap() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: Attempting to unwrap a DEK with a different KEK fails.
    let kek1 = pf_common::crypto::random_bytes(32).expect("KEK generation");
    let kek2 = pf_common::crypto::random_bytes(32).expect("KEK generation");
    let dek = Dek::generate().expect("DEK generation");

    let wrapped = encryption::wrap_dek(&kek1, "kek-original", &dek).expect("wrap");

    let result = encryption::unwrap_dek(&kek2, &wrapped);
    assert!(
        result.is_err(),
        "unwrap with wrong KEK must fail: got {result:?}"
    );
}

#[test]
fn nist_sc12_secrets_not_in_debug_output() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: DEK key material never appears in the Debug representation,
    // preventing accidental leakage in log output.
    let dek = Dek::generate().expect("DEK generation");
    let debug_str = format!("{dek:?}");

    assert_eq!(debug_str, "Dek(***)");
    assert!(
        !debug_str.contains("key_bytes"),
        "Debug must not reveal the field name"
    );

    // Also verify that the raw key bytes (as decimal values) do not appear.
    // The Debug output should be opaque and fixed-length.
    assert!(
        debug_str.len() < 20,
        "Debug output must be short and opaque, not contain key data"
    );
}

#[test]
fn nist_sc12_kek_id_preserved_in_wrapped_dek() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: The KEK ID used for wrapping is stored in the WrappedDek
    // so the correct KEK can be selected during unwrap / key rotation.
    let kek = pf_common::crypto::random_bytes(32).expect("KEK generation");
    let dek = Dek::generate().expect("DEK generation");
    let kek_id = "rotation-kek-2026-04";

    let wrapped = encryption::wrap_dek(&kek, kek_id, &dek).expect("wrap");
    assert_eq!(wrapped.kek_id, kek_id);
}

#[test]
fn nist_sc12_wrapped_dek_serialization_round_trip() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: WrappedDek can be serialized to JSON and deserialized back,
    // which is required for metadata storage alongside spool objects.
    let kek = pf_common::crypto::random_bytes(32).expect("KEK generation");
    let dek = Dek::generate().expect("DEK generation");

    let wrapped = encryption::wrap_dek(&kek, "json-test-kek", &dek).expect("wrap");

    let json = serde_json::to_string(&wrapped).expect("serialize");
    let deserialized: WrappedDek = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.kek_id, wrapped.kek_id);
    assert_eq!(deserialized.payload.nonce, wrapped.payload.nonce);
    assert_eq!(deserialized.payload.ciphertext, wrapped.payload.ciphertext);

    // Verify that the deserialized wrapped DEK can still be unwrapped.
    let unwrapped = encryption::unwrap_dek(&kek, &deserialized).expect("unwrap after deser");
    assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
}

// ---------------------------------------------------------------------------
// Key store tests (NIST SC-12)
// ---------------------------------------------------------------------------

#[test]
fn nist_sc12_in_memory_key_store_multiple_keks() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: Multiple KEKs can coexist in the store, supporting
    // key rotation where old KEKs decrypt legacy data while a new KEK
    // is used for new encryptions.
    let store = InMemoryKeyStore::new();
    let kek_old = pf_common::crypto::random_bytes(32).expect("kek gen");
    let kek_new = pf_common::crypto::random_bytes(32).expect("kek gen");

    store.insert("kek-2025-q4", kek_old.clone(), true).expect("insert old");
    store.insert("kek-2026-q1", kek_new.clone(), true).expect("insert new");

    // Active key should be the last one set as active.
    assert_eq!(store.active_kek_id().expect("active id"), "kek-2026-q1");

    // Both keys should be retrievable.
    assert_eq!(store.get_kek("kek-2025-q4").expect("get old"), kek_old);
    assert_eq!(store.get_kek("kek-2026-q1").expect("get new"), kek_new);
}

#[test]
fn nist_sc12_in_memory_key_store_with_generated_kek() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: The convenience constructor creates a functional store with
    // a randomly generated 256-bit KEK.
    let store = InMemoryKeyStore::with_generated_kek("auto-kek")
        .expect("generated key store");
    let (id, key) = store.active_kek().expect("active kek");
    assert_eq!(id, "auto-kek");
    assert_eq!(key.len(), 32, "KEK must be 256 bits");
}

#[test]
fn nist_sc12_end_to_end_encrypt_with_key_store() {
    // NIST 800-53 Rev 5: SC-12 + SC-28
    // Evidence: Full flow from key store through encryption and decryption.
    let store = InMemoryKeyStore::with_generated_kek("e2e-kek")
        .expect("key store creation");
    let (kek_id, kek) = store.active_kek().expect("active kek");

    // Generate DEK, encrypt data, wrap DEK.
    let dek = Dek::generate().expect("DEK generation");
    let plaintext = b"End-to-end integration test spool data";
    let encrypted = encryption::encrypt(&dek, plaintext).expect("encrypt");
    let wrapped = encryption::wrap_dek(&kek, &kek_id, &dek).expect("wrap");

    // Simulate retrieval: look up KEK from store, unwrap DEK, decrypt data.
    let retrieved_kek = store.get_kek(&wrapped.kek_id).expect("kek lookup");
    let unwrapped_dek = encryption::unwrap_dek(&retrieved_kek, &wrapped)
        .expect("unwrap");
    let decrypted = encryption::decrypt(&unwrapped_dek, &encrypted)
        .expect("decrypt");

    assert_eq!(&decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// Retention policy tests
// ---------------------------------------------------------------------------

#[test]
fn retention_period_calculation() {
    // Verify that RetentionPolicy correctly computes expires_at from
    // stored_at + retention duration.
    let stored_at = Utc::now();
    let retention = TimeDelta::hours(24);
    let policy = RetentionPolicy::new(stored_at, retention);

    assert_eq!(policy.stored_at, stored_at);
    assert_eq!(policy.expires_at, stored_at + retention);
}

#[test]
fn expired_spool_entries_identified_correctly() {
    // Entries stored far enough in the past with short retention windows
    // must be flagged as expired.
    let two_hours_ago = Utc::now() - TimeDelta::hours(2);
    let policy = RetentionPolicy::new(two_hours_ago, TimeDelta::hours(1));

    assert!(
        policy.is_expired(),
        "policy stored 2h ago with 1h retention must be expired"
    );
    assert_eq!(
        policy.time_remaining(),
        Duration::ZERO,
        "expired policy must have zero time remaining"
    );
}

#[test]
fn non_expired_entries_preserved() {
    // Entries within their retention window must NOT be flagged as expired.
    let now = Utc::now();
    let policy = RetentionPolicy::new(now, TimeDelta::hours(24));

    assert!(
        !policy.is_expired(),
        "freshly stored entry with 24h retention must not be expired"
    );
    assert!(
        policy.time_remaining() > Duration::ZERO,
        "non-expired policy must have positive time remaining"
    );
}

#[test]
fn retention_is_expired_at_with_explicit_timestamp() {
    // Verify the is_expired_at method using controlled timestamps.
    let stored_at = Utc::now();
    let retention = TimeDelta::hours(6);
    let policy = RetentionPolicy::new(stored_at, retention);

    let before = stored_at + TimeDelta::hours(3);
    let exactly = stored_at + TimeDelta::hours(6);
    let after = stored_at + TimeDelta::hours(9);

    assert!(!policy.is_expired_at(before), "must not be expired before window");
    assert!(policy.is_expired_at(exactly), "must be expired at exact boundary");
    assert!(policy.is_expired_at(after), "must be expired after window");
}

#[test]
fn find_expired_filters_mixed_candidates() {
    // Verify that retention::find_expired returns only expired entries.
    let now = Utc::now();
    let candidates = vec![
        // Expired: stored 4h ago, expired 1h ago
        (
            "job-expired-1".to_string(),
            now - TimeDelta::hours(4),
            now - TimeDelta::hours(1),
        ),
        // Not expired: stored now, expires in 6h
        (
            "job-active".to_string(),
            now,
            now + TimeDelta::hours(6),
        ),
        // Expired: stored 10h ago, expired 3h ago
        (
            "job-expired-2".to_string(),
            now - TimeDelta::hours(10),
            now - TimeDelta::hours(3),
        ),
        // Not expired: stored 1h ago, expires in 23h
        (
            "job-recent".to_string(),
            now - TimeDelta::hours(1),
            now + TimeDelta::hours(23),
        ),
    ];

    let expired = retention::find_expired(&candidates);
    assert_eq!(expired.len(), 2);

    let ids: Vec<&str> = expired.iter().map(|c| c.job_id.as_str()).collect();
    assert!(ids.contains(&"job-expired-1"));
    assert!(ids.contains(&"job-expired-2"));
    assert!(!ids.contains(&"job-active"));
    assert!(!ids.contains(&"job-recent"));
}

#[test]
fn retention_policy_serialization_round_trip() {
    // RetentionPolicy must survive JSON serialization/deserialization.
    let stored_at = Utc::now();
    let policy = RetentionPolicy::new(stored_at, TimeDelta::days(7));

    let json = serde_json::to_string(&policy).expect("serialize");
    let deserialized: RetentionPolicy =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.stored_at, policy.stored_at);
    assert_eq!(deserialized.expires_at, policy.expires_at);
}

// ---------------------------------------------------------------------------
// Config tests
// ---------------------------------------------------------------------------

#[test]
fn config_serialization_round_trip() {
    // SpoolConfig must survive JSON serialization/deserialization.
    // Note: access_key_id and secret_access_key are #[serde(skip)] so they
    // will be None after deserialization — this is by design (secrets are
    // injected via environment, not config files).
    let config = SpoolConfig {
        endpoint: "https://rustfs.test.local:9000".to_string(),
        bucket: "test-spool-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key_id: None,
        secret_access_key: None,
        force_path_style: true,
        key_store: KeyStoreConfig::InMemory,
        retention: RetentionConfig {
            default_retention: Duration::from_secs(3 * 24 * 3600),
            purge_interval: Duration::from_secs(300),
            max_retention: Duration::from_secs(14 * 24 * 3600),
        },
    };

    let json = serde_json::to_string_pretty(&config).expect("serialize");
    let deserialized: SpoolConfig =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.endpoint, config.endpoint);
    assert_eq!(deserialized.bucket, config.bucket);
    assert_eq!(deserialized.region, config.region);
    assert_eq!(deserialized.force_path_style, config.force_path_style);
    assert!(
        deserialized.access_key_id.is_none(),
        "secrets must not survive serialization"
    );
    assert!(
        deserialized.secret_access_key.is_none(),
        "secrets must not survive serialization"
    );
}

#[test]
fn default_config_has_sensible_values() {
    let config = SpoolConfig::default();

    // Endpoint should be a valid localhost URL.
    assert!(
        config.endpoint.starts_with("https://"),
        "default endpoint must use HTTPS"
    );

    // Bucket must have a meaningful name.
    assert!(
        !config.bucket.is_empty(),
        "default bucket must not be empty"
    );

    // Path-style is required for RustFS.
    assert!(
        config.force_path_style,
        "force_path_style must default to true for RustFS"
    );

    // Retention defaults should be reasonable.
    let retention = &config.retention;
    assert!(
        retention.default_retention >= Duration::from_secs(24 * 3600),
        "default retention must be at least 1 day"
    );
    assert!(
        retention.max_retention >= retention.default_retention,
        "max retention must be >= default retention"
    );
    assert!(
        retention.purge_interval <= Duration::from_secs(3600),
        "purge interval must be at most 1 hour"
    );

    // Secrets must not be set by default.
    assert!(config.access_key_id.is_none());
    assert!(config.secret_access_key.is_none());
}

#[test]
fn config_vault_key_store_variant() {
    // Verify that the Vault variant of KeyStoreConfig serializes correctly.
    let config = KeyStoreConfig::Vault {
        url: "https://vault.printforge.mil:8200".to_string(),
        mount_path: "transit".to_string(),
        key_name: "spool-kek".to_string(),
    };

    let json = serde_json::to_string(&config).expect("serialize vault config");
    assert!(json.contains("vault"), "must serialize with type tag");
    assert!(json.contains("transit"));

    let deserialized: KeyStoreConfig =
        serde_json::from_str(&json).expect("deserialize vault config");
    match deserialized {
        KeyStoreConfig::Vault {
            url,
            mount_path,
            key_name,
        } => {
            assert_eq!(url, "https://vault.printforge.mil:8200");
            assert_eq!(mount_path, "transit");
            assert_eq!(key_name, "spool-kek");
        }
        KeyStoreConfig::InMemory => panic!("expected Vault variant"),
    }
}

// ---------------------------------------------------------------------------
// Encrypted payload serialization tests
// ---------------------------------------------------------------------------

#[test]
fn encrypted_payload_serialization_round_trip() {
    // EncryptedPayload must survive JSON serialization for S3 storage.
    let dek = Dek::generate().expect("DEK generation");
    let plaintext = b"Payload that will be stored as JSON in S3";

    let encrypted = encryption::encrypt(&dek, plaintext).expect("encrypt");

    let json = serde_json::to_vec(&encrypted).expect("serialize");
    let deserialized: EncryptedPayload =
        serde_json::from_slice(&json).expect("deserialize");

    assert_eq!(deserialized.nonce, encrypted.nonce);
    assert_eq!(deserialized.ciphertext, encrypted.ciphertext);

    // Verify the deserialized payload can still be decrypted.
    let decrypted = encryption::decrypt(&dek, &deserialized).expect("decrypt after deser");
    assert_eq!(&decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// DEK validation tests
// ---------------------------------------------------------------------------

#[test]
fn dek_from_bytes_validates_length() {
    // DEK must be exactly 32 bytes (256 bits).
    assert!(
        Dek::from_bytes(vec![0u8; 16]).is_err(),
        "128-bit key must be rejected"
    );
    assert!(
        Dek::from_bytes(vec![0u8; 31]).is_err(),
        "31-byte key must be rejected"
    );
    assert!(
        Dek::from_bytes(vec![0u8; 33]).is_err(),
        "33-byte key must be rejected"
    );
    assert!(
        Dek::from_bytes(vec![0u8; 32]).is_ok(),
        "32-byte key must be accepted"
    );
}

#[test]
fn nist_sc12_dek_is_256_bits() {
    // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
    // Evidence: Every generated DEK is exactly 256 bits (32 bytes).
    for _ in 0..10 {
        let dek = Dek::generate().expect("DEK generation");
        assert_eq!(
            dek.as_bytes().len(),
            32,
            "DEK must be exactly 32 bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// Key store error handling
// ---------------------------------------------------------------------------

#[test]
fn key_store_returns_kek_not_found_for_missing_id() {
    let store = InMemoryKeyStore::new();
    let result = store.get_kek("nonexistent-kek");
    assert!(
        matches!(result, Err(SpoolError::KekNotFound(_))),
        "missing KEK must return KekNotFound: got {result:?}"
    );
}

#[test]
fn key_store_returns_config_error_when_no_active_kek() {
    let store = InMemoryKeyStore::new();
    let result = store.active_kek_id();
    assert!(
        matches!(result, Err(SpoolError::Config(_))),
        "no active KEK must return Config error: got {result:?}"
    );
}

#[test]
fn key_store_rejects_invalid_kek_length() {
    let store = InMemoryKeyStore::new();
    assert!(store.insert("bad-kek", vec![0u8; 16], true).is_err());
    assert!(store.insert("bad-kek", vec![0u8; 64], true).is_err());
    assert!(store.insert("good-kek", vec![0u8; 32], true).is_ok());
}
