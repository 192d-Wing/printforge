// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Vendor-specific firmware deployment dispatch.
//!
//! Each printer vendor has a different firmware push mechanism:
//! - HP: `OXP` (Open Extensibility Platform)
//! - Xerox: `CentreWare` Web Services
//! - Lexmark: Markvision (`MV`)
//! - Konica Minolta: `PageScope`
//!
//! The [`FirmwarePusher`] trait abstracts over these differences.

use std::future::Future;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterId;

use crate::error::FirmwareError;
use crate::registry::OciArtifactRef;

/// Result of a firmware push to a single printer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    /// The target printer.
    pub printer_id: PrinterId,

    /// The firmware artifact that was deployed.
    pub artifact_ref: OciArtifactRef,

    /// Whether the deployment succeeded.
    pub success: bool,

    /// Vendor-specific status message (for internal logging only).
    pub status_message: String,

    /// Duration of the deployment in seconds.
    pub duration_secs: u64,
}

/// Supported printer vendors for firmware deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Vendor {
    /// HP — firmware push via `OXP` (Open Extensibility Platform).
    Hp,
    /// Xerox — firmware push via `CentreWare` Web Services.
    Xerox,
    /// Lexmark — firmware push via `Markvision`.
    Lexmark,
    /// Konica Minolta — firmware push via `PageScope`.
    KonicaMinolta,
}

impl Vendor {
    /// Parse a vendor name string into a [`Vendor`] enum.
    ///
    /// Matching is case-insensitive. Recognizes common abbreviations.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Config`] if the vendor string is not recognized.
    pub fn from_name(name: &str) -> Result<Self, FirmwareError> {
        match name.to_ascii_lowercase().as_str() {
            "hp" | "hewlett-packard" => Ok(Self::Hp),
            "xerox" => Ok(Self::Xerox),
            "lexmark" => Ok(Self::Lexmark),
            "km" | "konica minolta" | "konicaminolta" => Ok(Self::KonicaMinolta),
            _ => Err(FirmwareError::Config {
                message: format!("unsupported vendor: {name}"),
            }),
        }
    }
}

/// Trait for pushing firmware to a printer via vendor-specific protocol.
///
/// **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
/// Implementations MUST verify the printer is reachable before pushing
/// and report accurate success/failure status.
pub trait FirmwarePusher: Send + Sync {
    /// The vendor this pusher handles.
    fn vendor(&self) -> Vendor;

    /// Push firmware to a single printer.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::DeploymentFailed`] if the firmware could not
    /// be pushed to the target printer.
    fn push_firmware(
        &self,
        printer_id: &PrinterId,
        artifact: &OciArtifactRef,
        firmware_data: &[u8],
    ) -> impl Future<Output = Result<DeploymentResult, FirmwareError>> + Send;

    /// Check whether a printer is reachable for firmware deployment.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::DeploymentFailed`] if the printer cannot be reached.
    fn check_reachability(
        &self,
        printer_id: &PrinterId,
    ) -> impl Future<Output = Result<bool, FirmwareError>> + Send;
}

/// Dispatch a firmware push to the correct vendor-specific implementation.
///
/// # Errors
///
/// Returns [`FirmwareError::Config`] if no pusher is registered for the
/// target vendor, or [`FirmwareError::DeploymentFailed`] if the push fails.
pub async fn dispatch_push(
    pushers: &[&dyn DynFirmwarePusher],
    vendor: Vendor,
    printer_id: &PrinterId,
    artifact: &OciArtifactRef,
    firmware_data: &[u8],
) -> Result<DeploymentResult, FirmwareError> {
    let pusher = pushers
        .iter()
        .find(|p| p.vendor() == vendor)
        .ok_or_else(|| FirmwareError::Config {
            message: format!("no pusher registered for vendor {vendor:?}"),
        })?;

    let deployment_id = Uuid::new_v4();
    tracing::info!(
        deployment_id = %deployment_id,
        vendor = ?vendor,
        printer_id = %printer_id.as_str(),
        artifact = %artifact.full_ref(),
        "dispatching firmware push"
    );

    pusher
        .push_firmware(printer_id, artifact, firmware_data)
        .await
}

/// Object-safe version of [`FirmwarePusher`] for dynamic dispatch.
pub trait DynFirmwarePusher: Send + Sync {
    /// The vendor this pusher handles.
    fn vendor(&self) -> Vendor;

    /// Push firmware to a single printer (boxed future for object safety).
    fn push_firmware(
        &self,
        printer_id: &PrinterId,
        artifact: &OciArtifactRef,
        firmware_data: &[u8],
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<DeploymentResult, FirmwareError>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_from_name_parses_hp() {
        assert_eq!(Vendor::from_name("HP").unwrap(), Vendor::Hp);
        assert_eq!(Vendor::from_name("hp").unwrap(), Vendor::Hp);
        assert_eq!(Vendor::from_name("hewlett-packard").unwrap(), Vendor::Hp);
    }

    #[test]
    fn vendor_from_name_parses_xerox() {
        assert_eq!(Vendor::from_name("Xerox").unwrap(), Vendor::Xerox);
    }

    #[test]
    fn vendor_from_name_parses_lexmark() {
        assert_eq!(Vendor::from_name("lexmark").unwrap(), Vendor::Lexmark);
    }

    #[test]
    fn vendor_from_name_parses_konica_minolta() {
        assert_eq!(Vendor::from_name("KM").unwrap(), Vendor::KonicaMinolta);
        assert_eq!(
            Vendor::from_name("konica minolta").unwrap(),
            Vendor::KonicaMinolta
        );
    }

    #[test]
    fn vendor_from_name_rejects_unknown() {
        let result = Vendor::from_name("Unknown Vendor");
        assert!(matches!(result, Err(FirmwareError::Config { .. })));
    }

    #[test]
    fn deployment_result_round_trips_json() {
        let result = DeploymentResult {
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            artifact_ref: OciArtifactRef {
                registry_url: url::Url::parse("https://registry.printforge.mil").unwrap(),
                repository: "firmware/hp/m612".to_string(),
                tag: "4.11.2.1".to_string(),
                digest: "sha256:abc".to_string(),
            },
            success: true,
            status_message: "Firmware update completed".to_string(),
            duration_secs: 120,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: DeploymentResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.duration_secs, 120);
    }
}
