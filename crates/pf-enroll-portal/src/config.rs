// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Enrollment portal configuration.
//!
//! Configures `IdP` endpoints, driver download paths, banner text,
//! and enclave detection for the self-service enrollment portal.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

/// Network enclave in which `PrintForge` is deployed.
///
/// Determined from deployment configuration (environment variable),
/// not from network sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Enclave {
    /// Non-classified Internet Protocol Router Network.
    /// Uses `Entra ID` via `OIDC`.
    Nipr,
    /// Secret Internet Protocol Router Network.
    /// Uses DISA E-ICAM via `SAML` 2.0.
    Sipr,
}

impl Enclave {
    /// Return the human-readable label for the sign-in button.
    #[must_use]
    pub fn sign_in_label(&self) -> &'static str {
        match self {
            Self::Nipr => "Sign in with DoD Entra ID",
            Self::Sipr => "Sign in with E-ICAM",
        }
    }
}

/// Top-level enrollment portal configuration.
///
/// Loaded from environment variables or a configuration file at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollPortalConfig {
    /// The network enclave this instance serves.
    pub enclave: Enclave,

    /// `OIDC` configuration (required on `NIPR`).
    pub oidc: Option<OidcEnrollConfig>,

    /// `SAML` configuration (required on `SIPR`).
    pub saml: Option<SamlEnrollConfig>,

    /// Base URL of the enrollment portal (for constructing callback URLs).
    pub portal_base_url: Url,

    /// Driver download hub configuration.
    pub driver_hub: DriverHubConfig,

    /// `DoD` consent banner configuration.
    ///
    /// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
    pub banner: BannerConfig,
}

/// `OIDC`-specific enrollment configuration (wraps `pf-auth` `OidcConfig`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcEnrollConfig {
    /// `OIDC` issuer URL.
    pub issuer_url: Url,
    /// OAuth 2.0 client ID.
    pub client_id: String,
    /// Redirect URI for the enrollment callback.
    pub redirect_uri: Url,
    /// Scopes to request.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".to_string(), "profile".to_string()]
}

/// `SAML`-specific enrollment configuration (wraps `pf-auth` `SamlConfig`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlEnrollConfig {
    /// `IdP` metadata URL.
    pub idp_metadata_url: Url,
    /// SP entity ID.
    pub sp_entity_id: String,
    /// Assertion Consumer Service URL.
    pub acs_url: Url,
}

/// Driver download hub configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverHubConfig {
    /// Directory containing driver packages.
    pub packages_dir: PathBuf,
    /// Base URL for constructing download links.
    pub download_base_url: Url,
}

/// `DoD` consent/use notification banner configuration.
///
/// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerConfig {
    /// The banner title.
    #[serde(default = "default_banner_title")]
    pub title: String,

    /// The full banner text displayed to users before `IdP` redirect.
    #[serde(default = "default_banner_text")]
    pub text: String,

    /// Label for the acknowledgment button.
    #[serde(default = "default_banner_accept_label")]
    pub accept_label: String,
}

fn default_banner_title() -> String {
    "U.S. Department of Defense Information System".to_string()
}

fn default_banner_text() -> String {
    "You are accessing a U.S. Government (USG) Information System (IS) that is \
     provided for USG-authorized use only. By using this IS (which includes any \
     device attached to this IS), you consent to the following conditions:\n\n\
     - The USG routinely intercepts and monitors communications on this IS for \
     purposes including, but not limited to, penetration testing, COMSEC \
     monitoring, network operations and defense, personnel misconduct (PM), \
     law enforcement (LE), and counterintelligence (CI) investigations.\n\
     - At any time, the USG may inspect and seize data stored on this IS.\n\
     - Communications using, or data stored on, this IS are not private, are \
     subject to routine monitoring, interception, and search, and may be \
     disclosed or used for any USG-authorized purpose.\n\
     - This IS includes security measures (e.g., authentication and access \
     controls) to protect USG interests--not for your personal benefit or \
     privacy.\n\
     - Notwithstanding the above, using this IS does not constitute consent to \
     PM, LE or CI investigative searching or monitoring of the content of \
     privileged communications, or work product, related to personal \
     representation or services by attorneys, psychotherapists, or clergy, and \
     their assistants. Such communications and work product are private and \
     confidential. See User Agreement for details."
        .to_string()
}

fn default_banner_accept_label() -> String {
    "I Accept".to_string()
}

impl Default for BannerConfig {
    fn default() -> Self {
        Self {
            title: default_banner_title(),
            text: default_banner_text(),
            accept_label: default_banner_accept_label(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enclave_sign_in_label_nipr() {
        assert_eq!(Enclave::Nipr.sign_in_label(), "Sign in with DoD Entra ID");
    }

    #[test]
    fn enclave_sign_in_label_sipr() {
        assert_eq!(Enclave::Sipr.sign_in_label(), "Sign in with E-ICAM");
    }

    #[test]
    fn default_banner_config_has_dod_text() {
        let cfg = BannerConfig::default();
        assert!(cfg.title.contains("Department of Defense"));
        assert!(cfg.text.contains("U.S. Government"));
        assert_eq!(cfg.accept_label, "I Accept");
    }

    #[test]
    fn nist_ac8_banner_contains_required_elements() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Banner text contains required notification elements.
        let cfg = BannerConfig::default();
        assert!(cfg.text.contains("monitoring"));
        assert!(cfg.text.contains("consent"));
        assert!(cfg.text.contains("USG-authorized"));
    }
}
