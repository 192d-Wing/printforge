// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Driver package listing, OS auto-detection, and signed download links.
//!
//! Provides a catalog of driver packages for different operating systems
//! and architectures. Each package includes a SHA-256 checksum for
//! integrity verification.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::DriverHubConfig;
use crate::error::EnrollmentError;

/// Supported operating systems for driver packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatingSystem {
    /// Microsoft Windows.
    Windows,
    /// macOS / OS X.
    MacOs,
    /// Linux (generic).
    Linux,
}

impl OperatingSystem {
    /// Detect the operating system from a `User-Agent` string.
    ///
    /// Returns `None` if the OS cannot be determined.
    #[must_use]
    pub fn from_user_agent(user_agent: &str) -> Option<Self> {
        let ua = user_agent.to_ascii_lowercase();
        if ua.contains("windows") || ua.contains("win64") || ua.contains("win32") {
            Some(Self::Windows)
        } else if ua.contains("macintosh") || ua.contains("mac os") {
            Some(Self::MacOs)
        } else if ua.contains("linux") || ua.contains("x11") {
            Some(Self::Linux)
        } else {
            None
        }
    }

    /// Return a display-friendly label for this OS.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::MacOs => "macOS",
            Self::Linux => "Linux",
        }
    }
}

/// CPU architecture for driver packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    /// 64-bit x86 (AMD64 / Intel 64).
    X86_64,
    /// 64-bit ARM (Apple Silicon, ARM servers).
    Aarch64,
}

impl Architecture {
    /// Return a display-friendly label for this architecture.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// A driver package available for download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverPackage {
    /// Package identifier (e.g., `"pf-driver-win-x64-1.2.0"`).
    pub id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Target operating system.
    pub os: OperatingSystem,
    /// Target architecture.
    pub arch: Architecture,
    /// Package version string.
    pub version: String,
    /// File name of the package.
    pub filename: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// SHA-256 checksum of the package file (hex-encoded).
    pub sha256: String,
}

/// A download link for a driver package with integrity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverDownloadLink {
    /// The package metadata.
    pub package: DriverPackage,
    /// Fully qualified download URL.
    pub download_url: Url,
    /// Whether this is the recommended package for the detected OS.
    pub recommended: bool,
}

/// Build the list of available driver download links, highlighting the
/// recommended package for the detected OS.
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if download URL construction fails.
pub fn build_download_links(
    config: &DriverHubConfig,
    packages: &[DriverPackage],
    detected_os: Option<OperatingSystem>,
) -> Result<Vec<DriverDownloadLink>, EnrollmentError> {
    let mut links = Vec::with_capacity(packages.len());

    for pkg in packages {
        let download_url = config.download_base_url.join(&pkg.filename).map_err(|e| {
            EnrollmentError::Internal(format!(
                "failed to construct download URL for {}: {e}",
                pkg.filename
            ))
        })?;

        let recommended = detected_os.is_some_and(|os| os == pkg.os);

        links.push(DriverDownloadLink {
            package: pkg.clone(),
            download_url,
            recommended,
        });
    }

    Ok(links)
}

/// Look up a specific driver package by OS and architecture.
///
/// # Errors
///
/// Returns `EnrollmentError::DriverNotFound` if no matching package exists.
pub fn find_package(
    packages: &[DriverPackage],
    os: OperatingSystem,
    arch: Architecture,
) -> Result<&DriverPackage, EnrollmentError> {
    packages
        .iter()
        .find(|p| p.os == os && p.arch == arch)
        .ok_or_else(|| EnrollmentError::DriverNotFound {
            os: os.label().to_string(),
            arch: arch.label().to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_packages() -> Vec<DriverPackage> {
        vec![
            DriverPackage {
                id: "pf-driver-win-x64-1.0.0".to_string(),
                display_name: "PrintForge Driver for Windows (x64)".to_string(),
                os: OperatingSystem::Windows,
                arch: Architecture::X86_64,
                version: "1.0.0".to_string(),
                filename: "pf-driver-win-x64-1.0.0.msi".to_string(),
                size_bytes: 15_000_000,
                sha256: "a".repeat(64),
            },
            DriverPackage {
                id: "pf-driver-macos-arm64-1.0.0".to_string(),
                display_name: "PrintForge Driver for macOS (Apple Silicon)".to_string(),
                os: OperatingSystem::MacOs,
                arch: Architecture::Aarch64,
                version: "1.0.0".to_string(),
                filename: "pf-driver-macos-arm64-1.0.0.pkg".to_string(),
                size_bytes: 12_000_000,
                sha256: "b".repeat(64),
            },
            DriverPackage {
                id: "pf-driver-linux-x64-1.0.0".to_string(),
                display_name: "PrintForge Driver for Linux (x64)".to_string(),
                os: OperatingSystem::Linux,
                arch: Architecture::X86_64,
                version: "1.0.0".to_string(),
                filename: "pf-driver-linux-x64-1.0.0.deb".to_string(),
                size_bytes: 8_000_000,
                sha256: "c".repeat(64),
            },
        ]
    }

    fn test_hub_config() -> DriverHubConfig {
        DriverHubConfig {
            packages_dir: PathBuf::from("/opt/printforge/drivers"),
            download_base_url: Url::parse("https://printforge.local/drivers/").unwrap(),
        }
    }

    #[test]
    fn os_detection_from_user_agent_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        assert_eq!(
            OperatingSystem::from_user_agent(ua),
            Some(OperatingSystem::Windows)
        );
    }

    #[test]
    fn os_detection_from_user_agent_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
        assert_eq!(
            OperatingSystem::from_user_agent(ua),
            Some(OperatingSystem::MacOs)
        );
    }

    #[test]
    fn os_detection_from_user_agent_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36";
        assert_eq!(
            OperatingSystem::from_user_agent(ua),
            Some(OperatingSystem::Linux)
        );
    }

    #[test]
    fn os_detection_from_unknown_agent_returns_none() {
        assert!(OperatingSystem::from_user_agent("curl/7.88.1").is_none());
    }

    #[test]
    fn build_download_links_marks_recommended() {
        let config = test_hub_config();
        let packages = test_packages();

        let links =
            build_download_links(&config, &packages, Some(OperatingSystem::Windows)).unwrap();

        assert_eq!(links.len(), 3);
        let windows_link = links
            .iter()
            .find(|l| l.package.os == OperatingSystem::Windows)
            .unwrap();
        assert!(windows_link.recommended);

        let macos_link = links
            .iter()
            .find(|l| l.package.os == OperatingSystem::MacOs)
            .unwrap();
        assert!(!macos_link.recommended);
    }

    #[test]
    fn build_download_links_no_detected_os_marks_none_recommended() {
        let config = test_hub_config();
        let packages = test_packages();

        let links = build_download_links(&config, &packages, None).unwrap();
        assert!(links.iter().all(|l| !l.recommended));
    }

    #[test]
    fn download_links_include_sha256_checksum() {
        // Driver packages must include SHA-256 checksums for integrity verification.
        let config = test_hub_config();
        let packages = test_packages();

        let links = build_download_links(&config, &packages, None).unwrap();
        for link in &links {
            assert_eq!(
                link.package.sha256.len(),
                64,
                "SHA-256 should be 64 hex chars"
            );
        }
    }

    #[test]
    fn find_package_returns_matching() {
        let packages = test_packages();
        let pkg = find_package(&packages, OperatingSystem::Windows, Architecture::X86_64).unwrap();
        assert_eq!(pkg.os, OperatingSystem::Windows);
        assert_eq!(pkg.arch, Architecture::X86_64);
    }

    #[test]
    fn find_package_returns_not_found_for_missing() {
        let packages = test_packages();
        let result = find_package(&packages, OperatingSystem::Windows, Architecture::Aarch64);
        assert!(matches!(
            result,
            Err(EnrollmentError::DriverNotFound { .. })
        ));
    }

    #[test]
    fn download_url_is_correctly_constructed() {
        let config = test_hub_config();
        let packages = test_packages();

        let links = build_download_links(&config, &packages, None).unwrap();
        let win_link = links
            .iter()
            .find(|l| l.package.os == OperatingSystem::Windows)
            .unwrap();
        assert_eq!(
            win_link.download_url.as_str(),
            "https://printforge.local/drivers/pf-driver-win-x64-1.0.0.msi"
        );
    }
}
