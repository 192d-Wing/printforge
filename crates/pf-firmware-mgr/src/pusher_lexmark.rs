// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Lexmark Markvision firmware push client.
//!
//! Lexmark printers can be managed via the Markvision Enterprise (MV) platform,
//! which exposes a REST API for firmware lifecycle operations. Firmware updates
//! are pushed via an authenticated multipart upload to the device management
//! endpoint.
//!
//! **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation

use std::fmt;
use std::time::Instant;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

use pf_common::fleet::PrinterId;

use crate::deployment::{DeploymentResult, FirmwarePusher, Vendor};
use crate::error::FirmwareError;
use crate::registry::OciArtifactRef;

/// Lexmark Markvision firmware upload endpoint path.
const LEXMARK_FIRMWARE_UPLOAD_PATH: &str = "/cgi-bin/dynamic/printer/config/firmwareDeploy";

/// Lexmark Markvision firmware version query endpoint path.
const LEXMARK_FIRMWARE_VERSION_PATH: &str = "/cgi-bin/dynamic/printer/config/reports/deviceInfo";

/// Lexmark Markvision device status endpoint path.
const LEXMARK_STATUS_PATH: &str = "/webglue/rawcontent?c=Status";

/// Lexmark-specific error codes returned by the Markvision API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexmarkErrorCode {
    /// Device is busy with another operation.
    DeviceBusy,
    /// Firmware signature validation failed on-device.
    SignatureRejected,
    /// Firmware version is not applicable to this model.
    VersionNotApplicable,
    /// Authentication credentials rejected.
    AuthenticationFailed,
    /// Generic/unknown error.
    Unknown(u16),
}

impl LexmarkErrorCode {
    /// Map a Lexmark HTTP status or API error code to a typed error.
    #[must_use]
    pub fn from_status(code: u16) -> Self {
        match code {
            409 => Self::DeviceBusy,
            422 => Self::SignatureRejected,
            406 => Self::VersionNotApplicable,
            401 | 403 => Self::AuthenticationFailed,
            _ => Self::Unknown(code),
        }
    }

    /// Convert to a [`FirmwareError`] with an appropriate internal message.
    pub fn into_firmware_error(self) -> FirmwareError {
        let msg: Box<dyn std::error::Error + Send + Sync> = match self {
            Self::DeviceBusy => "Lexmark device busy, cannot accept firmware update".into(),
            Self::SignatureRejected => {
                "Lexmark device rejected firmware signature validation".into()
            }
            Self::VersionNotApplicable => {
                "firmware version not applicable to Lexmark device model".into()
            }
            Self::AuthenticationFailed => "Lexmark Markvision authentication failed".into(),
            Self::Unknown(code) => format!("Lexmark Markvision error code: {code}").into(),
        };
        FirmwareError::DeploymentFailed { source: msg }
    }
}

/// Configuration for the Lexmark Markvision firmware pusher.
///
/// Credentials are stored as [`SecretString`] to prevent accidental leakage.
#[derive(Clone, Serialize, Deserialize)]
pub struct LexmarkPusherConfig {
    /// Base URL pattern for Lexmark printer management interfaces.
    /// Use `{ip}` as a placeholder for the printer IP address.
    /// Example: `https://{ip}`
    pub base_url_pattern: String,

    /// Administrative username for the Markvision interface.
    pub admin_username: String,

    /// Administrative password (redacted in Debug output).
    #[serde(skip)]
    pub admin_password: SecretString,

    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,

    /// Upload timeout in seconds.
    pub upload_timeout_secs: u64,
}

impl fmt::Debug for LexmarkPusherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LexmarkPusherConfig")
            .field("base_url_pattern", &self.base_url_pattern)
            .field("admin_username", &self.admin_username)
            .field("admin_password", &"[REDACTED]")
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("upload_timeout_secs", &self.upload_timeout_secs)
            .finish()
    }
}

impl Default for LexmarkPusherConfig {
    fn default() -> Self {
        Self {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("changeme".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
        }
    }
}

/// Lexmark Markvision firmware push client.
///
/// **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
/// Pushes firmware updates to Lexmark printers via the Markvision REST API.
pub struct LexmarkFirmwarePusher {
    config: LexmarkPusherConfig,
}

impl LexmarkFirmwarePusher {
    /// Create a new Lexmark firmware pusher with the given configuration.
    #[must_use]
    pub fn new(config: LexmarkPusherConfig) -> Self {
        Self { config }
    }

    /// Build the management URL for a specific printer.
    fn management_url(&self, printer_id: &PrinterId, path: &str) -> Result<Url, FirmwareError> {
        let base = self
            .config
            .base_url_pattern
            .replace("{ip}", printer_id.as_str());
        let full = format!("{base}{path}");
        Url::parse(&full).map_err(|e| FirmwareError::Config {
            message: format!(
                "invalid Lexmark management URL for {}: {e}",
                printer_id.as_str()
            ),
        })
    }

    /// Query the current firmware version from the device (stub).
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::DeploymentFailed`] if the device cannot be reached.
    pub fn get_current_version(
        &self,
        printer_id: &PrinterId,
    ) -> Result<String, FirmwareError> {
        let url = self.management_url(printer_id, LEXMARK_FIRMWARE_VERSION_PATH)?;
        tracing::info!(
            vendor = "Lexmark",
            printer_id = %printer_id.as_str(),
            url = %url,
            "querying current firmware version via Markvision"
        );

        // Stub: in production, this would parse the HTML/JSON response from
        // the Lexmark deviceInfo endpoint.
        Ok("STUB_LEXMARK_VERSION".to_string())
    }
}

impl FirmwarePusher for LexmarkFirmwarePusher {
    fn vendor(&self) -> Vendor {
        Vendor::Lexmark
    }

    async fn push_firmware(
        &self,
        printer_id: &PrinterId,
        artifact: &OciArtifactRef,
        firmware_data: &[u8],
    ) -> Result<DeploymentResult, FirmwareError> {
        let url = self.management_url(printer_id, LEXMARK_FIRMWARE_UPLOAD_PATH)?;
        let start = Instant::now();

        tracing::info!(
            vendor = "Lexmark",
            printer_id = %printer_id.as_str(),
            artifact = %artifact.full_ref(),
            firmware_size = firmware_data.len(),
            url = %url,
            username = %self.config.admin_username,
            "pushing firmware via Lexmark Markvision (stubbed)"
        );

        // Stub: in production, this would:
        // 1. Authenticate to the Markvision interface
        // 2. Upload firmware binary to the firmwareDeploy endpoint
        // 3. Poll for completion status
        // 4. Verify the new firmware version on the device
        let _ = self.config.admin_password.expose_secret();

        let duration = start.elapsed();

        Ok(DeploymentResult {
            printer_id: printer_id.clone(),
            artifact_ref: artifact.clone(),
            success: true,
            status_message: format!(
                "Lexmark Markvision firmware push completed (stubbed) to {url}"
            ),
            duration_secs: duration.as_secs(),
        })
    }

    async fn check_reachability(
        &self,
        printer_id: &PrinterId,
    ) -> Result<bool, FirmwareError> {
        let url = self.management_url(printer_id, LEXMARK_STATUS_PATH)?;

        tracing::info!(
            vendor = "Lexmark",
            printer_id = %printer_id.as_str(),
            url = %url,
            "checking Lexmark Markvision reachability (stubbed)"
        );

        // Stub: in production, this would attempt an HTTPS GET to the
        // device status endpoint and check for a 200 response.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LexmarkPusherConfig {
        LexmarkPusherConfig {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("s3cret-lexmark-pass".to_string()),
            connect_timeout_secs: 5,
            upload_timeout_secs: 300,
        }
    }

    fn test_artifact() -> OciArtifactRef {
        OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/lexmark/cx825".to_string(),
            tag: "LW82.MC2.P345".to_string(),
            digest: "sha256:ghi789".to_string(),
        }
    }

    #[test]
    fn lexmark_config_serialization_round_trip() {
        let cfg = LexmarkPusherConfig {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("ignored".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: LexmarkPusherConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_url_pattern, "https://{ip}");
        assert_eq!(parsed.admin_username, "admin");
    }

    #[test]
    fn lexmark_config_debug_does_not_leak_password() {
        let cfg = test_config();
        let debug_output = format!("{cfg:?}");
        assert!(
            !debug_output.contains("s3cret-lexmark-pass"),
            "password leaked in Debug output"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn lexmark_pusher_returns_correct_vendor() {
        let pusher = LexmarkFirmwarePusher::new(test_config());
        assert_eq!(pusher.vendor(), Vendor::Lexmark);
    }

    #[tokio::test]
    async fn lexmark_push_firmware_produces_valid_deployment_result() {
        let pusher = LexmarkFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-2001").unwrap();
        let artifact = test_artifact();
        let firmware_data = b"fake-lexmark-firmware-binary";

        let result = pusher
            .push_firmware(&printer_id, &artifact, firmware_data)
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.printer_id.as_str(), "PRN-2001");
        assert!(result.status_message.contains("Lexmark Markvision"));
    }

    #[tokio::test]
    async fn lexmark_check_reachability_returns_true() {
        let pusher = LexmarkFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-2001").unwrap();

        let reachable = pusher.check_reachability(&printer_id).await.unwrap();
        assert!(reachable);
    }

    #[test]
    fn lexmark_get_current_version_returns_stub() {
        let pusher = LexmarkFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-2001").unwrap();

        let version = pusher.get_current_version(&printer_id).unwrap();
        assert!(!version.is_empty());
    }

    #[test]
    fn lexmark_error_code_maps_correctly() {
        assert_eq!(
            LexmarkErrorCode::from_status(409),
            LexmarkErrorCode::DeviceBusy
        );
        assert_eq!(
            LexmarkErrorCode::from_status(422),
            LexmarkErrorCode::SignatureRejected
        );
        assert_eq!(
            LexmarkErrorCode::from_status(406),
            LexmarkErrorCode::VersionNotApplicable
        );
        assert_eq!(
            LexmarkErrorCode::from_status(401),
            LexmarkErrorCode::AuthenticationFailed
        );
        assert_eq!(
            LexmarkErrorCode::from_status(999),
            LexmarkErrorCode::Unknown(999)
        );
    }

    #[test]
    fn lexmark_error_code_converts_to_firmware_error() {
        let err = LexmarkErrorCode::SignatureRejected.into_firmware_error();
        assert_eq!(err.to_string(), "deployment to printer failed");
    }
}
