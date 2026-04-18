// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Konica Minolta `PageScope` firmware push client.
//!
//! Konica Minolta printers are managed via the `PageScope` Web Connection
//! interface. Firmware updates are uploaded via an authenticated POST to
//! the device's embedded web server with a vendor-specific multipart format.
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

/// Konica Minolta `PageScope` firmware upload endpoint path.
const KM_FIRMWARE_UPLOAD_PATH: &str = "/wcd/system_firmware.xml";

/// Konica Minolta `PageScope` firmware version query endpoint path.
const KM_FIRMWARE_VERSION_PATH: &str = "/wcd/device_info.xml";

/// Konica Minolta `PageScope` device status endpoint path.
const KM_STATUS_PATH: &str = "/wcd/system_status.xml";

/// Konica Minolta-specific error codes returned by the `PageScope` API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmErrorCode {
    /// Device is currently processing a job and cannot accept firmware.
    DeviceBusy,
    /// Authentication to the `PageScope` interface failed.
    AuthenticationFailed,
    /// Firmware file format is not recognized by the device.
    InvalidFirmwareFormat,
    /// Firmware downgrade is not permitted by device policy.
    DowngradeBlocked,
    /// Generic/unknown error from the `PageScope` API.
    Unknown(u16),
}

impl KmErrorCode {
    /// Map a Konica Minolta HTTP status or XML fault code to a typed error.
    #[must_use]
    pub fn from_status(code: u16) -> Self {
        match code {
            503 => Self::DeviceBusy,
            401 | 403 => Self::AuthenticationFailed,
            415 => Self::InvalidFirmwareFormat,
            409 => Self::DowngradeBlocked,
            _ => Self::Unknown(code),
        }
    }

    /// Convert to a [`FirmwareError`] with an appropriate internal message.
    pub fn into_firmware_error(self) -> FirmwareError {
        let msg: Box<dyn std::error::Error + Send + Sync> = match self {
            Self::DeviceBusy => {
                "Konica Minolta device busy, cannot accept firmware update".into()
            }
            Self::AuthenticationFailed => "PageScope authentication failed".into(),
            Self::InvalidFirmwareFormat => {
                "firmware file format not recognized by Konica Minolta device".into()
            }
            Self::DowngradeBlocked => {
                "Konica Minolta device policy blocks firmware downgrade".into()
            }
            Self::Unknown(code) => format!("Konica Minolta PageScope error code: {code}").into(),
        };
        FirmwareError::DeploymentFailed { source: msg }
    }
}

/// Configuration for the Konica Minolta `PageScope` firmware pusher.
///
/// Credentials are stored as [`SecretString`] to prevent accidental leakage.
#[derive(Clone, Serialize, Deserialize)]
pub struct KmPusherConfig {
    /// Base URL pattern for Konica Minolta printer management interfaces.
    /// Use `{ip}` as a placeholder for the printer IP address.
    /// Example: `https://{ip}`
    pub base_url_pattern: String,

    /// Administrative username for the `PageScope` interface.
    pub admin_username: String,

    /// Administrative password (redacted in Debug output).
    #[serde(skip)]
    pub admin_password: SecretString,

    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,

    /// Upload timeout in seconds.
    pub upload_timeout_secs: u64,

    /// Whether to allow firmware downgrades (default: false).
    pub allow_downgrade: bool,
}

impl fmt::Debug for KmPusherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmPusherConfig")
            .field("base_url_pattern", &self.base_url_pattern)
            .field("admin_username", &self.admin_username)
            .field("admin_password", &"[REDACTED]")
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("upload_timeout_secs", &self.upload_timeout_secs)
            .field("allow_downgrade", &self.allow_downgrade)
            .finish()
    }
}

impl Default for KmPusherConfig {
    fn default() -> Self {
        Self {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("changeme".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
            allow_downgrade: false,
        }
    }
}

/// Konica Minolta `PageScope` firmware push client.
///
/// **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
/// Pushes firmware updates to Konica Minolta printers via the `PageScope` XML API.
pub struct KmFirmwarePusher {
    config: KmPusherConfig,
}

impl KmFirmwarePusher {
    /// Create a new Konica Minolta firmware pusher with the given configuration.
    #[must_use]
    pub fn new(config: KmPusherConfig) -> Self {
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
                "invalid Konica Minolta management URL for {}: {e}",
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
        let url = self.management_url(printer_id, KM_FIRMWARE_VERSION_PATH)?;
        tracing::info!(
            vendor = "KonicaMinolta",
            printer_id = %printer_id.as_str(),
            url = %url,
            "querying current firmware version via PageScope"
        );

        // Stub: in production, this would parse the XML response from
        // the PageScope device_info endpoint.
        Ok("STUB_KM_VERSION".to_string())
    }
}

impl FirmwarePusher for KmFirmwarePusher {
    fn vendor(&self) -> Vendor {
        Vendor::KonicaMinolta
    }

    async fn push_firmware(
        &self,
        printer_id: &PrinterId,
        artifact: &OciArtifactRef,
        firmware_data: &[u8],
    ) -> Result<DeploymentResult, FirmwareError> {
        let url = self.management_url(printer_id, KM_FIRMWARE_UPLOAD_PATH)?;
        let start = Instant::now();

        tracing::info!(
            vendor = "KonicaMinolta",
            printer_id = %printer_id.as_str(),
            artifact = %artifact.full_ref(),
            firmware_size = firmware_data.len(),
            url = %url,
            username = %self.config.admin_username,
            allow_downgrade = %self.config.allow_downgrade,
            "pushing firmware via Konica Minolta PageScope (stubbed)"
        );

        // Stub: in production, this would:
        // 1. Authenticate to PageScope via XML-based session management
        // 2. Upload firmware binary to the system_firmware endpoint
        // 3. Include downgrade policy flag in the request
        // 4. Poll device_info.xml until reboot completes
        // 5. Verify new firmware version matches expected artifact tag
        let _ = self.config.admin_password.expose_secret();

        let duration = start.elapsed();

        Ok(DeploymentResult {
            printer_id: printer_id.clone(),
            artifact_ref: artifact.clone(),
            success: true,
            status_message: format!(
                "Konica Minolta PageScope firmware push completed (stubbed) to {url}"
            ),
            duration_secs: duration.as_secs(),
        })
    }

    async fn check_reachability(
        &self,
        printer_id: &PrinterId,
    ) -> Result<bool, FirmwareError> {
        let url = self.management_url(printer_id, KM_STATUS_PATH)?;

        tracing::info!(
            vendor = "KonicaMinolta",
            printer_id = %printer_id.as_str(),
            url = %url,
            "checking Konica Minolta PageScope reachability (stubbed)"
        );

        // Stub: in production, this would attempt an HTTPS GET to the
        // system_status.xml endpoint and check for a valid XML response.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> KmPusherConfig {
        KmPusherConfig {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("s3cret-km-pass".to_string()),
            connect_timeout_secs: 5,
            upload_timeout_secs: 300,
            allow_downgrade: false,
        }
    }

    fn test_artifact() -> OciArtifactRef {
        OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/km/bizhub-c558".to_string(),
            tag: "G00-K7".to_string(),
            digest: "sha256:jkl012".to_string(),
        }
    }

    #[test]
    fn km_config_serialization_round_trip() {
        let cfg = KmPusherConfig {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("ignored".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
            allow_downgrade: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: KmPusherConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_url_pattern, "https://{ip}");
        assert_eq!(parsed.admin_username, "admin");
        assert!(!parsed.allow_downgrade);
    }

    #[test]
    fn km_config_debug_does_not_leak_password() {
        let cfg = test_config();
        let debug_output = format!("{cfg:?}");
        assert!(
            !debug_output.contains("s3cret-km-pass"),
            "password leaked in Debug output"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn km_pusher_returns_correct_vendor() {
        let pusher = KmFirmwarePusher::new(test_config());
        assert_eq!(pusher.vendor(), Vendor::KonicaMinolta);
    }

    #[tokio::test]
    async fn km_push_firmware_produces_valid_deployment_result() {
        let pusher = KmFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-3001").unwrap();
        let artifact = test_artifact();
        let firmware_data = b"fake-km-firmware-binary";

        let result = pusher
            .push_firmware(&printer_id, &artifact, firmware_data)
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.printer_id.as_str(), "PRN-3001");
        assert!(result.status_message.contains("Konica Minolta PageScope"));
    }

    #[tokio::test]
    async fn km_check_reachability_returns_true() {
        let pusher = KmFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-3001").unwrap();

        let reachable = pusher.check_reachability(&printer_id).await.unwrap();
        assert!(reachable);
    }

    #[test]
    fn km_get_current_version_returns_stub() {
        let pusher = KmFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-3001").unwrap();

        let version = pusher.get_current_version(&printer_id).unwrap();
        assert!(!version.is_empty());
    }

    #[test]
    fn km_error_code_maps_correctly() {
        assert_eq!(KmErrorCode::from_status(503), KmErrorCode::DeviceBusy);
        assert_eq!(
            KmErrorCode::from_status(401),
            KmErrorCode::AuthenticationFailed
        );
        assert_eq!(
            KmErrorCode::from_status(415),
            KmErrorCode::InvalidFirmwareFormat
        );
        assert_eq!(
            KmErrorCode::from_status(409),
            KmErrorCode::DowngradeBlocked
        );
        assert_eq!(KmErrorCode::from_status(999), KmErrorCode::Unknown(999));
    }

    #[test]
    fn km_error_code_converts_to_firmware_error() {
        let err = KmErrorCode::DowngradeBlocked.into_firmware_error();
        assert_eq!(err.to_string(), "deployment to printer failed");
    }
}
