// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `OCI` registry client for firmware artifact storage and versioning.
//!
//! Firmware binaries are stored as `OCI` artifacts (not container images)
//! in the platform's `OCI`-compatible registry. Each artifact is tagged with
//! `vendor/model:version`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use pf_common::fleet::PrinterModel;

use crate::error::FirmwareError;

/// Reference to a firmware artifact stored in the `OCI` registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciArtifactRef {
    /// Registry base URL.
    pub registry_url: Url,

    /// Repository path within the registry (e.g., `firmware/hp/laserjet-m612`).
    pub repository: String,

    /// Tag for this specific version (e.g., `4.11.2.1`).
    pub tag: String,

    /// The content digest (`sha256:<hex>`) for immutable reference.
    pub digest: String,
}

impl OciArtifactRef {
    /// Construct the full artifact reference string.
    ///
    /// Returns a string like `registry.example.com/firmware/hp/laserjet-m612:4.11.2.1`.
    #[must_use]
    pub fn full_ref(&self) -> String {
        let host = self.registry_url.host_str().unwrap_or("unknown-registry");
        format!(
            "{host}/{repo}:{tag}",
            repo = self.repository,
            tag = self.tag
        )
    }
}

/// Metadata stored alongside a firmware artifact in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Firmware record identifier.
    pub firmware_id: Uuid,

    /// Target printer model.
    pub model: PrinterModel,

    /// Firmware version string.
    pub version: String,

    /// SHA-256 hex digest of the firmware binary.
    pub sha256: String,

    /// When the artifact was pushed to the registry.
    pub pushed_at: DateTime<Utc>,

    /// Size of the firmware binary in bytes.
    pub size_bytes: u64,
}

/// Trait for interacting with the `OCI` registry for firmware storage.
///
/// Implementations handle pushing firmware binaries as `OCI` artifacts,
/// pulling them for deployment, and querying available versions.
pub trait FirmwareRegistry: Send + Sync {
    /// Push a validated firmware binary to the registry.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Registry`] if the push fails.
    fn push(
        &self,
        metadata: &ArtifactMetadata,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<OciArtifactRef, FirmwareError>> + Send;

    /// Pull a firmware binary from the registry by its artifact reference.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Registry`] if the pull fails, or
    /// [`FirmwareError::NotFound`] if the artifact does not exist.
    fn pull(
        &self,
        artifact: &OciArtifactRef,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FirmwareError>> + Send;

    /// List all available firmware versions for a given printer model.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Registry`] if the query fails.
    fn list_versions(
        &self,
        model: &PrinterModel,
    ) -> impl std::future::Future<Output = Result<Vec<ArtifactMetadata>, FirmwareError>> + Send;

    /// Resolve a model and version string to an artifact reference.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::NotFound`] if no matching artifact exists.
    fn resolve(
        &self,
        model: &PrinterModel,
        version: &str,
    ) -> impl std::future::Future<Output = Result<OciArtifactRef, FirmwareError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_artifact_ref_full_ref_format() {
        let artifact = OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/hp/laserjet-m612".to_string(),
            tag: "4.11.2.1".to_string(),
            digest: "sha256:abcdef1234567890".to_string(),
        };
        assert_eq!(
            artifact.full_ref(),
            "registry.printforge.mil/firmware/hp/laserjet-m612:4.11.2.1"
        );
    }

    #[test]
    fn artifact_metadata_round_trips_json() {
        let meta = ArtifactMetadata {
            firmware_id: Uuid::new_v4(),
            model: PrinterModel {
                vendor: "Xerox".to_string(),
                model: "VersaLink C405".to_string(),
            },
            version: "74.10.0".to_string(),
            sha256: "aabbccdd".to_string(),
            pushed_at: Utc::now(),
            size_bytes: 1_048_576,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ArtifactMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "74.10.0");
        assert_eq!(parsed.size_bytes, 1_048_576);
    }
}
