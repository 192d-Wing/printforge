// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Spool data store/retrieve/delete operations.
//!
//! **NIST 800-53 Rev 5:** SC-28 (Protection of Information at Rest),
//! SC-12 (Cryptographic Key Establishment).
//!
//! Every byte of spool data is encrypted before being written to `RustFS`.
//! There is no unencrypted storage path.

use chrono::{DateTime, Utc};
use pf_common::job::JobId;
use serde::{Deserialize, Serialize};

use crate::client::S3Client;
use crate::encryption::{self, Dek, WrappedDek};
use crate::error::SpoolError;
use crate::key_store::KeyStore;

/// Metadata stored alongside the encrypted spool object.
///
/// This record is stored as a separate S3 object (`<job-id>.meta.json`)
/// and contains the wrapped DEK and bookkeeping fields needed for
/// retrieval and retention enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoolMetadata {
    /// The job this spool data belongs to.
    pub job_id: String,
    /// The wrapped (encrypted) DEK for this spool object.
    pub wrapped_dek: WrappedDek,
    /// SHA-256 hex digest of the plaintext (for integrity verification).
    pub plaintext_sha256: String,
    /// Size of the plaintext in bytes.
    pub plaintext_size: u64,
    /// When this spool object was stored.
    pub stored_at: DateTime<Utc>,
    /// When this spool object becomes eligible for purge.
    pub expires_at: DateTime<Utc>,
    /// Content type hint (e.g., `application/pdf`, `application/vnd.hp-pcl`).
    pub content_type: String,
}

/// The result of a successful spool retrieval (decrypted data + metadata).
#[derive(Debug)]
pub struct SpoolRetrieveResult {
    /// Decrypted plaintext spool data.
    pub data: Vec<u8>,
    /// Metadata about the spool object.
    pub metadata: SpoolMetadata,
}

/// Request to store spool data.
#[derive(Debug)]
pub struct SpoolStoreRequest<'a> {
    /// Job identifier.
    pub job_id: &'a JobId,
    /// Plaintext spool data to encrypt and store.
    pub data: &'a [u8],
    /// Content type (e.g., `application/pdf`).
    pub content_type: &'a str,
    /// Retention duration from now.
    pub retention: chrono::Duration,
}

/// The encrypted spool data store.
///
/// Orchestrates encryption, key management, and S3 storage. Encryption is
/// mandatory — there is no unencrypted code path.
pub struct SpoolStore<K: KeyStore> {
    s3: S3Client,
    key_store: K,
}

impl<K: KeyStore> SpoolStore<K> {
    /// Create a new `SpoolStore` with the given S3 client and key store.
    #[must_use]
    pub fn new(s3: S3Client, key_store: K) -> Self {
        Self { s3, key_store }
    }

    /// Store encrypted spool data for a job.
    ///
    /// **NIST 800-53 Rev 5:** SC-28 — Protection of Information at Rest
    ///
    /// 1. Generates a per-job DEK
    /// 2. Encrypts the spool data with AES-256-GCM
    /// 3. Wraps the DEK with the active KEK
    /// 4. Uploads the ciphertext and metadata to S3
    ///
    /// # Errors
    ///
    /// Returns `SpoolError` on key generation, encryption, or S3 failures.
    pub async fn store(
        &self,
        request: &SpoolStoreRequest<'_>,
    ) -> Result<SpoolMetadata, SpoolError> {
        let job_id_str = request.job_id.as_uuid().to_string();
        tracing::info!(job_id = %job_id_str, "storing encrypted spool data");

        // 1. Generate per-job DEK
        let dek = Dek::generate()?;

        // 2. Encrypt spool data
        let encrypted = encryption::encrypt(&dek, request.data)?;
        let ciphertext_json = serde_json::to_vec(&encrypted)?;

        // 3. Wrap DEK with active KEK
        let (kek_id, kek) = self.key_store.active_kek()?;
        let wrapped_dek = encryption::wrap_dek(&kek, &kek_id, &dek)?;

        // 4. Compute plaintext hash for integrity verification
        let plaintext_sha256 = pf_common::crypto::sha256_hex(request.data);

        let now = Utc::now();
        let metadata = SpoolMetadata {
            job_id: job_id_str.clone(),
            wrapped_dek,
            plaintext_sha256,
            plaintext_size: request.data.len() as u64,
            stored_at: now,
            expires_at: now + request.retention,
            content_type: request.content_type.to_string(),
        };

        // Upload ciphertext
        let data_key = format!("{job_id_str}.enc");
        self.s3
            .put_object(&data_key, ciphertext_json, "application/octet-stream", None)
            .await?;

        // Upload metadata
        let meta_key = format!("{job_id_str}.meta.json");
        let meta_json = serde_json::to_vec(&metadata)?;
        self.s3
            .put_object(&meta_key, meta_json, "application/json", None)
            .await?;

        tracing::info!(
            job_id = %job_id_str,
            size = request.data.len(),
            expires_at = %metadata.expires_at,
            "spool data stored successfully"
        );

        Ok(metadata)
    }

    /// Retrieve and decrypt spool data for a job.
    ///
    /// **NIST 800-53 Rev 5:** SC-28 — Protection of Information at Rest
    ///
    /// 1. Downloads the metadata to get the wrapped DEK
    /// 2. Unwraps the DEK using the appropriate KEK
    /// 3. Downloads and decrypts the ciphertext
    /// 4. Verifies the plaintext hash
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::NotFound` if the spool object does not exist.
    /// Returns `SpoolError::IntegrityFailure` if the hash or GCM tag check fails.
    pub async fn retrieve(&self, job_id: &JobId) -> Result<SpoolRetrieveResult, SpoolError> {
        let job_id_str = job_id.as_uuid().to_string();
        tracing::info!(job_id = %job_id_str, "retrieving encrypted spool data");

        // 1. Download metadata
        let meta_key = format!("{job_id_str}.meta.json");
        let meta_bytes = self.s3.get_object(&meta_key).await?;
        let metadata: SpoolMetadata = serde_json::from_slice(&meta_bytes)?;

        // 2. Unwrap DEK
        let kek = self.key_store.get_kek(&metadata.wrapped_dek.kek_id)?;
        let dek = encryption::unwrap_dek(&kek, &metadata.wrapped_dek)?;

        // 3. Download and decrypt ciphertext
        let data_key = format!("{job_id_str}.enc");
        let ciphertext_bytes = self.s3.get_object(&data_key).await?;
        let encrypted: encryption::EncryptedPayload = serde_json::from_slice(&ciphertext_bytes)?;
        let plaintext = encryption::decrypt(&dek, &encrypted)?;

        // 4. Verify plaintext hash
        let actual_hash = pf_common::crypto::sha256_hex(&plaintext);
        if actual_hash != metadata.plaintext_sha256 {
            tracing::error!(
                job_id = %job_id_str,
                "plaintext hash mismatch after decryption"
            );
            return Err(SpoolError::IntegrityFailure);
        }

        tracing::info!(
            job_id = %job_id_str,
            size = plaintext.len(),
            "spool data retrieved and decrypted successfully"
        );

        Ok(SpoolRetrieveResult {
            data: plaintext,
            metadata,
        })
    }

    /// Delete spool data and its metadata for a job.
    ///
    /// Both the encrypted data object and the metadata object are removed.
    /// The wrapped DEK is destroyed along with the metadata.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Storage` if S3 deletion fails.
    pub async fn delete(&self, job_id: &JobId) -> Result<(), SpoolError> {
        let job_id_str = job_id.as_uuid().to_string();
        tracing::info!(job_id = %job_id_str, "deleting spool data");

        let data_key = format!("{job_id_str}.enc");
        let meta_key = format!("{job_id_str}.meta.json");

        self.s3.delete_object(&data_key).await?;
        self.s3.delete_object(&meta_key).await?;

        tracing::info!(job_id = %job_id_str, "spool data and metadata deleted");
        Ok(())
    }

    /// Check if spool data exists for a job.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Storage` on S3 communication failure.
    pub async fn exists(&self, job_id: &JobId) -> Result<bool, SpoolError> {
        let job_id_str = job_id.as_uuid().to_string();
        let data_key = format!("{job_id_str}.enc");
        self.s3.object_exists(&data_key).await
    }

    /// Return a reference to the underlying key store.
    pub fn key_store(&self) -> &K {
        &self.key_store
    }
}
