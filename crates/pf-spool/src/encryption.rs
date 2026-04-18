// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! DEK generation, KEK wrapping, and AES-256-GCM encrypt/decrypt.
//!
//! **NIST 800-53 Rev 5:** SC-28 (Protection of Information at Rest),
//! SC-12 (Cryptographic Key Establishment), SC-13 (Cryptographic Protection).
//!
//! Every spool object is encrypted with a per-job Data Encryption Key (DEK).
//! The DEK is wrapped (encrypted) by a Key Encryption Key (KEK) before storage.
//! This module uses `ring::aead::AES_256_GCM` for all symmetric encryption and
//! `ring::rand::SystemRandom` for key and nonce generation.

use ring::aead::{self, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, UnboundKey};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::error::SpoolError;

/// Length of an AES-256 key in bytes.
const AES_256_KEY_LEN: usize = 32;

/// A single-use nonce for AES-GCM.
///
/// Each encryption operation generates a fresh 96-bit random nonce.
/// This struct is consumed after one use to prevent nonce reuse.
struct SingleUseNonce(Option<[u8; NONCE_LEN]>);

impl SingleUseNonce {
    fn new(rng: &SystemRandom) -> Result<Self, SpoolError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| SpoolError::KeyGeneration("failed to generate nonce".to_string()))?;
        Ok(Self(Some(nonce_bytes)))
    }

    fn bytes(&self) -> &[u8; NONCE_LEN] {
        self.0.as_ref().expect("nonce already consumed")
    }
}

impl NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(Unspecified)
    }
}

/// A plaintext Data Encryption Key.
///
/// **SECURITY:** This type intentionally does NOT implement `Display` or `Serialize`.
/// DEK material must never appear in logs.
#[derive(Clone)]
pub struct Dek {
    key_bytes: Vec<u8>,
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(***)")
    }
}

impl Dek {
    /// Generate a fresh 256-bit DEK using `ring::rand::SystemRandom`.
    ///
    /// **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::KeyGeneration` if the system RNG fails.
    pub fn generate() -> Result<Self, SpoolError> {
        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; AES_256_KEY_LEN];
        rng.fill(&mut key_bytes)
            .map_err(|_| SpoolError::KeyGeneration("failed to generate DEK".to_string()))?;
        Ok(Self { key_bytes })
    }

    /// Reconstruct a DEK from raw bytes (e.g., after unwrapping from KEK).
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::KeyGeneration` if the key length is not 32 bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SpoolError> {
        if bytes.len() != AES_256_KEY_LEN {
            return Err(SpoolError::KeyGeneration(format!(
                "invalid DEK length: expected {AES_256_KEY_LEN}, got {}",
                bytes.len()
            )));
        }
        Ok(Self { key_bytes: bytes })
    }

    /// Return the raw key bytes. Use only for wrapping/unwrapping.
    ///
    /// **SECURITY:** Never log the return value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

/// Encrypted spool payload: nonce + ciphertext (with appended GCM tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// 96-bit random nonce used for this encryption.
    pub nonce: Vec<u8>,
    /// Ciphertext with the GCM authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Wrapped (encrypted) DEK stored alongside the spool object.
///
/// The `kek_id` identifies which KEK was used to wrap this DEK so that
/// key rotation can proceed without re-encrypting all spool data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDek {
    /// Identifier of the KEK that wrapped this DEK.
    pub kek_id: String,
    /// The DEK encrypted under the KEK (nonce + ciphertext).
    pub payload: EncryptedPayload,
}

/// Encrypt plaintext using AES-256-GCM with the given DEK.
///
/// **NIST 800-53 Rev 5:** SC-28 — Protection of Information at Rest
///
/// Each call generates a unique 96-bit random nonce.
///
/// # Errors
///
/// Returns `SpoolError::Encryption` if nonce generation or encryption fails.
pub fn encrypt(dek: &Dek, plaintext: &[u8]) -> Result<EncryptedPayload, SpoolError> {
    let rng = SystemRandom::new();
    let nonce = SingleUseNonce::new(&rng)?;
    let nonce_bytes = *nonce.bytes();

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, dek.as_bytes())
        .map_err(|_| SpoolError::Encryption("invalid key material".to_string()))?;

    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .map_err(|_| SpoolError::Encryption("AES-256-GCM seal failed".to_string()))?;

    Ok(EncryptedPayload {
        nonce: nonce_bytes.to_vec(),
        ciphertext: in_out,
    })
}

/// Decrypt an `EncryptedPayload` using AES-256-GCM with the given DEK.
///
/// **NIST 800-53 Rev 5:** SC-28 — Protection of Information at Rest
///
/// # Errors
///
/// Returns `SpoolError::IntegrityFailure` if the GCM tag does not verify
/// (indicating tampering or a wrong key). Returns `SpoolError::Encryption`
/// for other decryption failures.
pub fn decrypt(dek: &Dek, payload: &EncryptedPayload) -> Result<Vec<u8>, SpoolError> {
    if payload.nonce.len() != NONCE_LEN {
        return Err(SpoolError::Encryption(format!(
            "invalid nonce length: expected {NONCE_LEN}, got {}",
            payload.nonce.len()
        )));
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&payload.nonce);
    let nonce_seq = SingleUseNonce(Some(nonce_bytes));

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, dek.as_bytes())
        .map_err(|_| SpoolError::Encryption("invalid key material".to_string()))?;

    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

    let mut in_out = payload.ciphertext.clone();
    let plaintext = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| SpoolError::IntegrityFailure)?;

    Ok(plaintext.to_vec())
}

/// Wrap (encrypt) a DEK using a KEK. Uses AES-256-GCM.
///
/// **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment
///
/// # Errors
///
/// Returns `SpoolError::KeyWrap` on encryption failure.
pub fn wrap_dek(kek: &[u8], kek_id: &str, dek: &Dek) -> Result<WrappedDek, SpoolError> {
    let rng = SystemRandom::new();
    let nonce = SingleUseNonce::new(&rng)
        .map_err(|e| SpoolError::KeyWrap(format!("nonce generation: {e}")))?;
    let nonce_bytes = *nonce.bytes();

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, kek)
        .map_err(|_| SpoolError::KeyWrap("invalid KEK material".to_string()))?;

    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce);

    let mut in_out = dek.as_bytes().to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .map_err(|_| SpoolError::KeyWrap("AES-256-GCM wrap failed".to_string()))?;

    Ok(WrappedDek {
        kek_id: kek_id.to_string(),
        payload: EncryptedPayload {
            nonce: nonce_bytes.to_vec(),
            ciphertext: in_out,
        },
    })
}

/// Unwrap (decrypt) a wrapped DEK using the KEK.
///
/// **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment
///
/// # Errors
///
/// Returns `SpoolError::KeyWrap` on decryption failure or if the GCM tag
/// does not verify.
pub fn unwrap_dek(kek: &[u8], wrapped: &WrappedDek) -> Result<Dek, SpoolError> {
    if wrapped.payload.nonce.len() != NONCE_LEN {
        return Err(SpoolError::KeyWrap(format!(
            "invalid nonce length: expected {NONCE_LEN}, got {}",
            wrapped.payload.nonce.len()
        )));
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&wrapped.payload.nonce);
    let nonce_seq = SingleUseNonce(Some(nonce_bytes));

    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, kek)
        .map_err(|_| SpoolError::KeyWrap("invalid KEK material".to_string()))?;

    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

    let mut in_out = wrapped.payload.ciphertext.clone();
    let plaintext = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| {
            SpoolError::KeyWrap("DEK unwrap failed — wrong KEK or tampered data".to_string())
        })?;

    Dek::from_bytes(plaintext.to_vec())
        .map_err(|e| SpoolError::KeyWrap(format!("unwrapped DEK invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_sc28_encrypt_decrypt_round_trip() {
        // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
        // Evidence: Plaintext survives an encrypt-then-decrypt round trip.
        let dek = Dek::generate().unwrap();
        let plaintext = b"Sensitive print job spool data for USAF";

        let encrypted = encrypt(&dek, plaintext).unwrap();
        let decrypted = decrypt(&dek, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nist_sc28_ciphertext_differs_from_plaintext() {
        // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
        // Evidence: Ciphertext is not equal to plaintext.
        let dek = Dek::generate().unwrap();
        let plaintext = b"This should be encrypted, not stored in the clear";

        let encrypted = encrypt(&dek, plaintext).unwrap();

        assert_ne!(
            &encrypted.ciphertext[..plaintext.len()],
            plaintext.as_slice()
        );
    }

    #[test]
    fn nist_sc28_wrong_key_fails_decryption() {
        // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
        // Evidence: Decryption with a different key fails with IntegrityFailure.
        let dek1 = Dek::generate().unwrap();
        let dek2 = Dek::generate().unwrap();
        let plaintext = b"Confidential data";

        let encrypted = encrypt(&dek1, plaintext).unwrap();
        let result = decrypt(&dek2, &encrypted);

        assert!(matches!(result, Err(SpoolError::IntegrityFailure)));
    }

    #[test]
    fn nist_sc28_tampered_ciphertext_fails() {
        // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
        // Evidence: Tampering with ciphertext is detected by the GCM tag.
        let dek = Dek::generate().unwrap();
        let plaintext = b"Data that must not be tampered with";

        let mut encrypted = encrypt(&dek, plaintext).unwrap();
        // Flip a bit in the ciphertext
        if let Some(byte) = encrypted.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt(&dek, &encrypted);
        assert!(matches!(result, Err(SpoolError::IntegrityFailure)));
    }

    #[test]
    fn nist_sc12_dek_generation_produces_256_bit_key() {
        // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
        // Evidence: Generated DEK is exactly 256 bits (32 bytes).
        let dek = Dek::generate().unwrap();
        assert_eq!(dek.as_bytes().len(), 32);
    }

    #[test]
    fn nist_sc12_dek_generation_is_random() {
        // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
        // Evidence: Two generated DEKs are not identical.
        let dek1 = Dek::generate().unwrap();
        let dek2 = Dek::generate().unwrap();
        assert_ne!(dek1.as_bytes(), dek2.as_bytes());
    }

    #[test]
    fn nist_sc12_wrap_unwrap_dek_round_trip() {
        // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
        // Evidence: DEK survives wrap/unwrap with the correct KEK.
        let kek = pf_common::crypto::random_bytes(32).unwrap();
        let dek = Dek::generate().unwrap();
        let original_bytes = dek.as_bytes().to_vec();

        let wrapped = wrap_dek(&kek, "kek-001", &dek).unwrap();
        let unwrapped = unwrap_dek(&kek, &wrapped).unwrap();

        assert_eq!(unwrapped.as_bytes(), &original_bytes);
    }

    #[test]
    fn nist_sc12_wrong_kek_fails_unwrap() {
        // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
        // Evidence: Unwrapping with the wrong KEK fails.
        let kek1 = pf_common::crypto::random_bytes(32).unwrap();
        let kek2 = pf_common::crypto::random_bytes(32).unwrap();
        let dek = Dek::generate().unwrap();

        let wrapped = wrap_dek(&kek1, "kek-001", &dek).unwrap();
        let result = unwrap_dek(&kek2, &wrapped);

        assert!(result.is_err());
    }

    #[test]
    fn nist_sc28_unique_nonce_per_encryption() {
        // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
        // Evidence: Each encryption produces a unique nonce.
        let dek = Dek::generate().unwrap();
        let plaintext = b"Same plaintext, different nonces";

        let enc1 = encrypt(&dek, plaintext).unwrap();
        let enc2 = encrypt(&dek, plaintext).unwrap();

        assert_ne!(enc1.nonce, enc2.nonce);
    }

    #[test]
    fn nist_sc28_encrypt_empty_data() {
        // NIST 800-53 Rev 5: SC-28 — Protection of Information at Rest
        // Evidence: Empty data can be encrypted and decrypted.
        let dek = Dek::generate().unwrap();
        let plaintext = b"";

        let encrypted = encrypt(&dek, plaintext).unwrap();
        // Ciphertext should be exactly the GCM tag length (16 bytes)
        assert_eq!(encrypted.ciphertext.len(), 16);

        let decrypted = decrypt(&dek, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn dek_from_bytes_rejects_wrong_length() {
        assert!(Dek::from_bytes(vec![0u8; 16]).is_err());
        assert!(Dek::from_bytes(vec![0u8; 64]).is_err());
    }

    #[test]
    fn dek_debug_does_not_leak_key() {
        let dek = Dek::generate().unwrap();
        let debug = format!("{dek:?}");
        assert_eq!(debug, "Dek(***)");
        assert!(!debug.contains("key_bytes"));
    }
}
