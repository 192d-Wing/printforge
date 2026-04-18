// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! HP OXP (Open Extensibility Platform) firmware push client.
//!
//! HP printers expose a REST-based management API via OXP. Firmware updates
//! are uploaded as multipart form data to the device's embedded web server.
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

/// HP OXP firmware upload endpoint path.
const HP_FIRMWARE_UPLOAD_PATH: &str = "/hp/device/firmware/upload";

/// HP OXP firmware version query endpoint path.
const HP_FIRMWARE_VERSION_PATH: &str = "/hp/device/info/firmware";

/// HP OXP device status endpoint path.
const HP_STATUS_PATH: &str = "/hp/device/info/status";

/// Configuration for the HP OXP firmware pusher.
///
/// Credentials are stored as [`SecretString`] to prevent accidental leakage
/// in logs or debug output.
#[derive(Clone, Serialize, Deserialize)]
pub struct HpPusherConfig {
    /// Base URL pattern for HP printer management interfaces.
    /// Use `{ip}` as a placeholder for the printer IP address.
    /// Example: `https://{ip}:443`
    pub base_url_pattern: String,

    /// Administrative username for the OXP interface.
    pub admin_username: String,

    /// Administrative password (redacted in Debug output).
    #[serde(skip)]
    pub admin_password: SecretString,

    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,

    /// Upload timeout in seconds (firmware files can be large).
    pub upload_timeout_secs: u64,
}

impl fmt::Debug for HpPusherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpPusherConfig")
            .field("base_url_pattern", &self.base_url_pattern)
            .field("admin_username", &self.admin_username)
            .field("admin_password", &"[REDACTED]")
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("upload_timeout_secs", &self.upload_timeout_secs)
            .finish()
    }
}

impl Default for HpPusherConfig {
    fn default() -> Self {
        Self {
            base_url_pattern: "https://{ip}:443".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("changeme".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
        }
    }
}

/// HP OXP firmware push client.
///
/// **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
/// Pushes firmware updates to HP printers via the OXP REST API.
pub struct HpFirmwarePusher {
    config: HpPusherConfig,
}

impl HpFirmwarePusher {
    /// Create a new HP firmware pusher with the given configuration.
    #[must_use]
    pub fn new(config: HpPusherConfig) -> Self {
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
            message: format!("invalid HP management URL for {}: {e}", printer_id.as_str()),
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
        let url = self.management_url(printer_id, HP_FIRMWARE_VERSION_PATH)?;
        tracing::info!(
            vendor = "HP",
            printer_id = %printer_id.as_str(),
            url = %url,
            "querying current firmware version via OXP"
        );

        // Stub: in production, this would make an HTTPS GET request
        // to the HP OXP firmware version endpoint.
        Ok("STUB_HP_VERSION".to_string())
    }
}

impl FirmwarePusher for HpFirmwarePusher {
    fn vendor(&self) -> Vendor {
        Vendor::Hp
    }

    async fn push_firmware(
        &self,
        printer_id: &PrinterId,
        artifact: &OciArtifactRef,
        firmware_data: &[u8],
    ) -> Result<DeploymentResult, FirmwareError> {
        let url = self.management_url(printer_id, HP_FIRMWARE_UPLOAD_PATH)?;
        let start = Instant::now();

        tracing::info!(
            vendor = "HP",
            printer_id = %printer_id.as_str(),
            artifact = %artifact.full_ref(),
            firmware_size = firmware_data.len(),
            url = %url,
            username = %self.config.admin_username,
            "pushing firmware via HP OXP (stubbed)"
        );

        // Stub: in production, this would:
        // 1. Authenticate to the OXP interface with admin credentials
        // 2. Upload firmware_data as multipart/form-data to the upload endpoint
        // 3. Monitor the upload progress
        // 4. Verify the device reboots and reports the new version
        let _ = self.config.admin_password.expose_secret();

        let duration = start.elapsed();

        Ok(DeploymentResult {
            printer_id: printer_id.clone(),
            artifact_ref: artifact.clone(),
            success: true,
            status_message: format!("HP OXP firmware push completed (stubbed) to {url}"),
            duration_secs: duration.as_secs(),
        })
    }

    async fn check_reachability(
        &self,
        printer_id: &PrinterId,
    ) -> Result<bool, FirmwareError> {
        let url = self.management_url(printer_id, HP_STATUS_PATH)?;

        tracing::info!(
            vendor = "HP",
            printer_id = %printer_id.as_str(),
            url = %url,
            "checking HP OXP reachability (stubbed)"
        );

        // Stub: in production, this would attempt an HTTPS GET to the
        // device status endpoint and check for a 200 response.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HpPusherConfig {
        HpPusherConfig {
            base_url_pattern: "https://{ip}:443".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("s3cret-hp-pass".to_string()),
            connect_timeout_secs: 5,
            upload_timeout_secs: 300,
        }
    }

    fn test_artifact() -> OciArtifactRef {
        OciArtifactRef {
            registry_url: Url::parse("https://registry.printforge.mil").unwrap(),
            repository: "firmware/hp/laserjet-m612".to_string(),
            tag: "4.11.2.1".to_string(),
            digest: "sha256:abc123".to_string(),
        }
    }

    #[test]
    fn hp_config_serialization_round_trip() {
        let cfg = HpPusherConfig {
            base_url_pattern: "https://{ip}:443".to_string(),
            admin_username: "admin".to_string(),
            admin_password: SecretString::from("ignored".to_string()),
            connect_timeout_secs: 10,
            upload_timeout_secs: 600,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: HpPusherConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_url_pattern, "https://{ip}:443");
        assert_eq!(parsed.admin_username, "admin");
        assert_eq!(parsed.connect_timeout_secs, 10);
    }

    #[test]
    fn hp_config_debug_does_not_leak_password() {
        let cfg = test_config();
        let debug_output = format!("{cfg:?}");
        assert!(
            !debug_output.contains("s3cret-hp-pass"),
            "password leaked in Debug output"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn hp_pusher_returns_correct_vendor() {
        let pusher = HpFirmwarePusher::new(test_config());
        assert_eq!(pusher.vendor(), Vendor::Hp);
    }

    #[tokio::test]
    async fn hp_push_firmware_produces_valid_deployment_result() {
        let pusher = HpFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-0042").unwrap();
        let artifact = test_artifact();
        let firmware_data = b"fake-firmware-binary-data";

        let result = pusher
            .push_firmware(&printer_id, &artifact, firmware_data)
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.printer_id.as_str(), "PRN-0042");
        assert!(result.status_message.contains("HP OXP"));
    }

    #[tokio::test]
    async fn hp_check_reachability_returns_true() {
        let pusher = HpFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-0042").unwrap();

        let reachable = pusher.check_reachability(&printer_id).await.unwrap();
        assert!(reachable);
    }

    #[test]
    fn hp_get_current_version_returns_stub() {
        let pusher = HpFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-0042").unwrap();

        let version = pusher.get_current_version(&printer_id).unwrap();
        assert!(!version.is_empty());
    }

    #[test]
    fn hp_management_url_builds_correctly() {
        let pusher = HpFirmwarePusher::new(test_config());
        let printer_id = PrinterId::new("PRN-0042").unwrap();

        let url = pusher
            .management_url(&printer_id, HP_FIRMWARE_UPLOAD_PATH)
            .unwrap();
        // URL host is lowercased by the parser, so check case-insensitively.
        let url_lower = url.as_str().to_ascii_lowercase();
        assert!(url_lower.contains("prn-0042"));
        assert!(url.as_str().contains("/hp/device/firmware/upload"));
    }
}
