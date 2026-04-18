// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! KEK storage trait and implementations.
//!
//! **NIST 800-53 Rev 5:** SC-12 — Cryptographic Key Establishment
//!
//! In production, KEKs are stored in `HashiCorp` Vault's transit engine.
//! An in-memory implementation is provided for development and testing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::SpoolError;

/// Trait for key stores that manage Key Encryption Keys (KEKs).
///
/// Implementations must securely store and retrieve KEKs by ID. In production
/// this is backed by `HashiCorp` Vault; for development the `InMemoryKeyStore`
/// is provided.
pub trait KeyStore: Send + Sync {
    /// Retrieve a KEK by its identifier.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::KekNotFound` if no KEK exists with the given ID.
    /// Returns `SpoolError::Storage` on backend communication failure.
    fn get_kek(&self, kek_id: &str) -> Result<Vec<u8>, SpoolError>;

    /// Return the identifier of the current (active) KEK for new encryptions.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Config` if no active KEK is configured.
    fn active_kek_id(&self) -> Result<String, SpoolError>;

    /// Retrieve the active KEK (convenience method).
    ///
    /// # Errors
    ///
    /// Returns errors from `active_kek_id` or `get_kek`.
    fn active_kek(&self) -> Result<(String, Vec<u8>), SpoolError> {
        let id = self.active_kek_id()?;
        let key = self.get_kek(&id)?;
        Ok((id, key))
    }
}

/// In-memory KEK store for development and testing.
///
/// **WARNING:** This implementation stores key material in process memory
/// without hardware protection. Do NOT use in production. Production
/// deployments MUST use `HashiCorp` Vault.
#[derive(Debug, Clone)]
pub struct InMemoryKeyStore {
    keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    active_id: Arc<Mutex<Option<String>>>,
}

impl InMemoryKeyStore {
    /// Create a new empty in-memory key store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            active_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Insert a KEK and optionally set it as the active key.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::KeyGeneration` if the key is not 32 bytes.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (indicates a prior thread panic).
    pub fn insert(&self, kek_id: &str, key: Vec<u8>, set_active: bool) -> Result<(), SpoolError> {
        if key.len() != 32 {
            return Err(SpoolError::KeyGeneration(format!(
                "KEK must be 32 bytes, got {}",
                key.len()
            )));
        }
        let mut keys = self.keys.lock().expect("key store lock poisoned");
        keys.insert(kek_id.to_string(), key);

        if set_active {
            let mut active = self.active_id.lock().expect("active_id lock poisoned");
            *active = Some(kek_id.to_string());
        }
        Ok(())
    }

    /// Create a store pre-loaded with a single generated KEK for testing.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::KeyGeneration` if random byte generation fails.
    pub fn with_generated_kek(kek_id: &str) -> Result<Self, SpoolError> {
        let store = Self::new();
        let key = pf_common::crypto::random_bytes(32)
            .map_err(|e| SpoolError::KeyGeneration(format!("KEK generation: {e}")))?;
        store.insert(kek_id, key, true)?;
        Ok(store)
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for InMemoryKeyStore {
    fn get_kek(&self, kek_id: &str) -> Result<Vec<u8>, SpoolError> {
        let keys = self.keys.lock().expect("key store lock poisoned");
        keys.get(kek_id)
            .cloned()
            .ok_or_else(|| SpoolError::KekNotFound(kek_id.to_string()))
    }

    fn active_kek_id(&self) -> Result<String, SpoolError> {
        let active = self.active_id.lock().expect("active_id lock poisoned");
        active
            .clone()
            .ok_or_else(|| SpoolError::Config("no active KEK configured".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_round_trip() {
        let store = InMemoryKeyStore::new();
        let key = pf_common::crypto::random_bytes(32).unwrap();
        store.insert("kek-001", key.clone(), true).unwrap();

        assert_eq!(store.active_kek_id().unwrap(), "kek-001");
        assert_eq!(store.get_kek("kek-001").unwrap(), key);
    }

    #[test]
    fn in_memory_store_kek_not_found() {
        let store = InMemoryKeyStore::new();
        assert!(matches!(
            store.get_kek("nonexistent"),
            Err(SpoolError::KekNotFound(_))
        ));
    }

    #[test]
    fn in_memory_store_no_active_kek() {
        let store = InMemoryKeyStore::new();
        assert!(matches!(store.active_kek_id(), Err(SpoolError::Config(_))));
    }

    #[test]
    fn in_memory_store_rejects_short_kek() {
        let store = InMemoryKeyStore::new();
        assert!(store.insert("kek-bad", vec![0u8; 16], true).is_err());
    }

    #[test]
    fn nist_sc12_key_rotation_supports_multiple_keks() {
        // NIST 800-53 Rev 5: SC-12 — Cryptographic Key Establishment
        // Evidence: Multiple KEKs can be stored and the active one switched.
        let store = InMemoryKeyStore::new();
        let key1 = pf_common::crypto::random_bytes(32).unwrap();
        let key2 = pf_common::crypto::random_bytes(32).unwrap();

        store.insert("kek-001", key1.clone(), true).unwrap();
        store.insert("kek-002", key2.clone(), true).unwrap();

        // Active is now kek-002
        assert_eq!(store.active_kek_id().unwrap(), "kek-002");

        // But kek-001 is still available for decrypting old data
        assert_eq!(store.get_kek("kek-001").unwrap(), key1);
        assert_eq!(store.get_kek("kek-002").unwrap(), key2);
    }

    #[test]
    fn with_generated_kek_creates_store() {
        let store = InMemoryKeyStore::with_generated_kek("test-kek").unwrap();
        assert_eq!(store.active_kek_id().unwrap(), "test-kek");
        assert_eq!(store.get_kek("test-kek").unwrap().len(), 32);
    }
}
