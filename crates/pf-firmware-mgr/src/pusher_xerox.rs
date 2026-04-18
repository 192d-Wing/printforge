// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Xerox `CentreWare` Web Services firmware push client.
//!
//! Xerox printers expose a SOAP-based management API via `CentreWare` Internet
//! Services. Firmware updates are uploaded via a multipart POST to the embedded
//! web server.
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

/// Xerox `CentreWare` firmware upload endpoint path.
const XEROX_FIRMWARE_UPLOAD_PATH: &str = "/webglue/rawcontent?c=firmware_upgrade";

/// Xerox `CentreWare` firmware version query endpoint path.
const XEROX_FIRMWARE_VERSION_PATH: &str = "/ssm/Management/Anonymous/StatusConfig";

/// Xerox `CentreWare` device status endpoint path.
const XEROX_STATUS_PATH: &str = "/ssm/Management/Anonymous/DeviceStatus";

/// Xerox-specific error codes returned by the `CentreWare` API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XeroxErrorCode {
    /// Device is busy processing another firmware update.
    DeviceBusy,
    /// Authentication failed for the management interface.
    AuthenticationFailed,
    /// Uploaded firmware file is incompatible with the device model.
    IncompatibleFirmware,
    /// The device ran out of storage during the upload.
    InsufficientStorage,
    /// Generic/unknown error from the `CentreWare` API.
    Unknown(u16),
}

impl XeroxErrorCode {
    /// Map a Xerox `CentreWare` HTTP status or SOAP fault code to a typed error.
    #[must_use]
    pub fn from_status(code: u16) -> Self {
        match code {
            503 => Self::DeviceBusy,
            401 | 403 => Self::AuthenticationFailed,
            415 => Self::IncompatibleFirmware,
            507 => Self::InsufficientStorage,
            _ => Self::Unknown(code),
        }
    }

    /// Convert to a [`FirmwareError`] with an appropriate internal message.
    pub fn into_firmware_error(self) -> FirmwareError {
        let msg: Box<dyn std::error::Error + Send + Sync> = match self {
            Self::DeviceBusy => "Xerox device busy, firmware update in progress".into(),
            Self::AuthenticationFailed => "Xerox CentreWare authentication failed".into(),
            Self::IncompatibleFirmware => "firmware incompatible with Xerox device model".into(),
            Self::InsufficientStorage => "Xerox device has insufficient storage".into(),
            Self::Unknown(code) => format!("Xerox CentreWare error code: {code}").into(),
        };
        FirmwareError::DeploymentFailed { source: msg }
    }
}

/// Configuration for the Xerox `CentreWare` firmware pusher.
///
/// Credentials are stored as [`SecretString`] to prevent accidental leakage.
#[derive(Clone, Serialize, Deserialize)]
pub struct XeroxPusherConfig {
    /// Base URL pattern for Xerox printer management interfaces.
    /// Use `{ip}` as a placeholder for the printer IP address.
    /// Example: `https://{ip}`
    pub base_url_pattern: String,

    /// Administrative username for the `CentreWare` interface.
    pub admin_username: String,

    /// Administrative password (redacted in Debug output).
    #[serde(skip)]
    pub admin_password: SecretString,

    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,

    /// Upload timeout in seconds.
    pub upload_timeout_secs: u64,
}

impl fmt::Debug for XeroxPusherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XeroxPusherConfig")
            .field("base_url_pattern", &self.base_url_pattern)
            .field("admin_username", &self.admin_username)
            .field("admin_password", &"[REDACTED]")
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("upload_timeout_secs", &self.upload_timeout_secs)
            .finish()
    }
}

impl Default for XeroxPusherConfig {
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

/// Xerox `CentreWare` firmware push client.
///
/// **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
/// Pushes firmware updates to Xerox printers via the `CentreWare` Web Services API.
pub struct XeroxFirmwarePusher {
    config: XeroxPusherConfig,
}

impl XeroxFirmwarePusher {
    /// Create a new Xerox firmware pusher with the given configuration.
    #[must_use]
    pub fn new(config: XeroxPusherConfig) -> Self {
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
                "invalid Xerox management URL for {}: {e}",
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
        let url = self.management_url(printer_id, XEROX_FIRMWARE_VERSION_PATH)?;
        tracing::info!(
            vendor = "Xerox",
            printer_id = %printer_id.as_str(),
            url = %url,
            "querying current firmware version via CentreWare"
        );

        // Stub: in production, this would parse XML/SOAP response from
        // the CentreWare StatusConfig endpoint.
        Ok("STUB_XEROX_VERSION".to_string())
    }
}

impl FirmwarePusher for XeroxFirmwarePusher {
    fn vendor(&self) -> Vendor {
        Vendor::Xerox
    }

    async fn push_firmware(
        &self,
        printer_id: &PrinterId,
        artifact: &OciArtifactRef,
        firmware_data: &[u8],
    ) -> Result<DeploymentResult, FirmwareError> {
        let url = self.management_url(printer_id, XEROX_FIRMWARE_UPLOAD_PATH)?;
        let start = Instant::now();

        tracing::info!(
            vendor = "Xerox",
            printer_id = %printer_id.as_str(),
            artifact = %artifact.full_ref(),
            firmware_size = firmware_data.len(),
            url = %url,
            username = %self.config.admin_username,
            "pushing firmware via Xerox CentreWare (stubbed)"
        );

        // Stub: in production, this would:
        // 1. Authenticate to CentreWare via SOAP/HTTP Basic Auth
        // 2. Upload firmware as multipart POST to the firmware_upgrade endpoint
        // 3. Poll device status until reboot completes
        // 4. Verify new firmware version matches expected artifact tag
        let _ = self.config.admin_password.expose_secret();

        let duration = start.elapsed();

        Ok(DeploymentResult {
            printer_id: printer_id.clone(),
            artifact_ref: artifact.clone(),
            success: true,
            status_message: format!(
                "Xerox CentreWare firmware push completed (stubbed) to {url}"
            ),
            duration_secs: duration.as_secs(),
        })
    }

    async fn check_reachability(
        &self,
        printer_id: &PrinterId,
    ) -> Result<bool, FirmwareError> {
        let url = self.management_url(printer_id, XEROX_STATUS_PATH)?;

        tracing::info!(
            vendor = "Xerox",
            printer_id = %printer_id.as_str(),
            url = %url,
            "checking Xerox CentreWare reachability (stubbed)"
        );

        // Stub: in production, this would attempt an HTTPS GET to the
        // device status endpoint and check for a 200 response.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> XeroxPusherConfig {
        XeroxPusherConfig {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("s3cret-xerox-pass".to_string()),
            connect_timeout_secs: 5,
            upload_timeout_secs: 300,
        }
    }

    fn test_artifact() -> OciArtifactRef {
        OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/xerox/versalink-c405".to_string(),
            tag: "73.10.21".to_string(),
            digest: "sha256:def456".to_string(),
        }
    }

    #[test]
    fn xerox_config_serialization_round_trip() {
        let cfg = XeroxPusherConfig {
            base_url_pattern: "https://{ip}".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("ignored".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: XeroxPusherConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_url_pattern, "https://{ip}");
        assert_eq!(parsed.admin_username, "admin");
    }

    #[test]
    fn xerox_config_debug_does_not_leak_password() {
        let cfg = test_config();
        let debug_output = format!("{cfg:?}");
        assert!(
            !debug_output.contains("s3cret-xerox-pass"),
            "password leaked in Debug output"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn xerox_pusher_returns_correct_vendor() {
        let pusher = XeroxFirmwarePusher::new(test_config());
        assert_eq!(pusher.vendor(), Vendor::Xerox);
    }

    #[tokio::test]
    async fn xerox_push_firmware_produces_valid_deployment_result() {
        let pusher = XeroxFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-1001").unwrap();
        let artifact = test_artifact();
        let firmware_data = b"fake-xerox-firmware-binary";

        let result = pusher
            .push_firmware(&printer_id, &artifact, firmware_data)
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.printer_id.as_str(), "PRN-1001");
        assert!(result.status_message.contains("Xerox CentreWare"));
    }

    #[tokio::test]
    async fn xerox_check_reachability_returns_true() {
        let pusher = XeroxFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-1001").unwrap();

        let reachable = pusher.check_reachability(&printer_id).await.unwrap();
        assert!(reachable);
    }

    #[test]
    fn xerox_get_current_version_returns_stub() {
        let pusher = XeroxFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-1001").unwrap();

        let version = pusher.get_current_version(&printer_id).unwrap();
        assert!(!version.is_empty());
    }

    #[test]
    fn xerox_error_code_maps_correctly() {
        assert_eq!(
            XeroxErrorCode::from_status(503),
            XeroxErrorCode::DeviceBusy
        );
        assert_eq!(
            XeroxErrorCode::from_status(401),
            XeroxErrorCode::AuthenticationFailed
        );
        assert_eq!(
            XeroxErrorCode::from_status(415),
            XeroxErrorCode::IncompatibleFirmware
        );
        assert_eq!(
            XeroxErrorCode::from_status(507),
            XeroxErrorCode::InsufficientStorage
        );
        assert_eq!(
            XeroxErrorCode::from_status(999),
            XeroxErrorCode::Unknown(999)
        );
    }

    #[test]
    fn xerox_error_code_converts_to_firmware_error() {
        let err = XeroxErrorCode::DeviceBusy.into_firmware_error();
        // Should be DeploymentFailed, and display message should NOT leak internals.
        assert_eq!(err.to_string(), "deployment to printer failed");
    }
}
