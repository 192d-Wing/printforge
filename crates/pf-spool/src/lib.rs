// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Encrypted spool store for `PrintForge` via `RustFS` S3.
//!
//! **NIST 800-53 Rev 5:** SC-28 (Protection of Information at Rest),
//! SC-12 (Cryptographic Key Establishment), SC-13 (Cryptographic Protection).
//!
//! Every print job's spool data (rendered PDF/PCL6) is encrypted at rest with
//! a per-job AES-256-GCM Data Encryption Key (DEK). DEKs are wrapped by a
//! Key Encryption Key (KEK) before storage, enabling key rotation without
//! re-encrypting all spool data.
//!
//! Encryption is **mandatory** — there is no unencrypted storage path.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod encryption;
pub mod error;
pub mod key_store;
pub mod retention;
pub mod spool;

pub use config::SpoolConfig;
pub use encryption::{Dek, EncryptedPayload, WrappedDek};
pub use error::SpoolError;
pub use key_store::{InMemoryKeyStore, KeyStore};
pub use retention::RetentionPolicy;
pub use spool::{SpoolMetadata, SpoolRetrieveResult, SpoolStore, SpoolStoreRequest};
