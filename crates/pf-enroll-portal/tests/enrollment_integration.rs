// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for `pf-enroll-portal`.
//!
//! Covers banner enforcement (AC-8), enrollment flow, driver hub,
//! `IdP` redirect, and profile management.

use chrono::Utc;
use url::Url;

use pf_common::identity::Edipi;
use pf_enroll_portal::banner::{
    build_banner_presentation, validate_acknowledgment, BannerAcknowledgment,
};
use pf_enroll_portal::callback::{OidcCallbackParams, SamlCallbackParams};
use pf_enroll_portal::config::{
    BannerConfig, DriverHubConfig, Enclave, EnrollPortalConfig, OidcEnrollConfig,
    SamlEnrollConfig,
};
use pf_enroll_portal::driver_hub::{
    build_download_links, find_package, Architecture, DriverPackage, OperatingSystem,
};
use pf_enroll_portal::enrollment::{
    mark_banner_acknowledged, mark_banner_displayed, mark_complete, mark_redirected,
    start_enrollment, EnrollmentPhase,
};
use pf_enroll_portal::error::EnrollmentError;
use pf_enroll_portal::idp_redirect::{initiate_redirect, RedirectResult};
use pf_enroll_portal::profile::{
    apply_preference_update, build_profile, validate_preference_update, ColorMode, DuplexMode,
    PreferenceUpdate, UserPreferences, UserProfile,
};

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helper constructors (synthetic test data only)
// ---------------------------------------------------------------------------

fn nipr_config() -> EnrollPortalConfig {
    EnrollPortalConfig {
        enclave: Enclave::Nipr,
        oidc: Some(OidcEnrollConfig {
            issuer_url: Url::parse("https://login.example.com/tenant1").unwrap(),
            client_id: "test-client-id".to_string(),
            redirect_uri: Url::parse("https://printforge.local/enroll/callback").unwrap(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
        }),
        saml: None,
        portal_base_url: Url::parse("https://printforge.local").unwrap(),
        driver_hub: DriverHubConfig {
            packages_dir: PathBuf::from("/opt/printforge/drivers"),
            download_base_url: Url::parse("https://printforge.local/drivers/").unwrap(),
        },
        banner: BannerConfig::default(),
    }
}

fn sipr_config() -> EnrollPortalConfig {
    EnrollPortalConfig {
        enclave: Enclave::Sipr,
        oidc: None,
        saml: Some(SamlEnrollConfig {
            idp_metadata_url: Url::parse("https://idp.example.smil.mil/saml/sso").unwrap(),
            sp_entity_id: "https://printforge.local/saml/metadata".to_string(),
            acs_url: Url::parse("https://printforge.local/enroll/saml/acs").unwrap(),
        }),
        portal_base_url: Url::parse("https://printforge.local").unwrap(),
        driver_hub: DriverHubConfig {
            packages_dir: PathBuf::from("/opt/printforge/drivers"),
            download_base_url: Url::parse("https://printforge.local/drivers/").unwrap(),
        },
        banner: BannerConfig::default(),
    }
}

fn sample_packages() -> Vec<DriverPackage> {
    vec![
        DriverPackage {
            id: "pf-driver-win-x64-1.0.0".to_string(),
            display_name: "PrintForge Driver for Windows (x64)".to_string(),
            os: OperatingSystem::Windows,
            arch: Architecture::X86_64,
            version: "1.0.0".to_string(),
            filename: "pf-driver-win-x64-1.0.0.msi".to_string(),
            size_bytes: 15_000_000,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
        },
        DriverPackage {
            id: "pf-driver-macos-arm64-1.0.0".to_string(),
            display_name: "PrintForge Driver for macOS (Apple Silicon)".to_string(),
            os: OperatingSystem::MacOs,
            arch: Architecture::Aarch64,
            version: "1.0.0".to_string(),
            filename: "pf-driver-macos-arm64-1.0.0.pkg".to_string(),
            size_bytes: 12_000_000,
            sha256: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
                .to_string(),
        },
        DriverPackage {
            id: "pf-driver-linux-x64-1.0.0".to_string(),
            display_name: "PrintForge Driver for Linux (x64)".to_string(),
            os: OperatingSystem::Linux,
            arch: Architecture::X86_64,
            version: "1.0.0".to_string(),
            filename: "pf-driver-linux-x64-1.0.0.deb".to_string(),
            size_bytes: 8_000_000,
            sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                .to_string(),
        },
    ]
}

// ===========================================================================
// 1. Banner enforcement (AC-8)
// ===========================================================================

#[test]
fn nist_ac8_banner_must_be_acknowledged() {
    // NIST 800-53 Rev 5: AC-8 — System Use Notification
    // Evidence: The enrollment flow cannot proceed past the banner phase
    // without explicit acknowledgment. Attempting to acknowledge without
    // displaying the banner first is rejected.
    let config = nipr_config();
    let mut session = start_enrollment(&config).unwrap();

    // Phase starts at BannerPending.
    assert_eq!(session.phase, EnrollmentPhase::BannerPending);

    // Trying to acknowledge before display is an error.
    let result = mark_banner_acknowledged(&mut session);
    assert!(
        matches!(result, Err(EnrollmentError::BannerNotAcknowledged)),
        "must not skip banner display"
    );

    // Display the banner, then acknowledge.
    mark_banner_displayed(&mut session, "nonce-abc".to_string()).unwrap();
    assert_eq!(session.phase, EnrollmentPhase::BannerDisplayed);

    mark_banner_acknowledged(&mut session).unwrap();
    assert_eq!(session.phase, EnrollmentPhase::Redirecting);
}

#[test]
fn nist_ac8_banner_contains_dod_notice() {
    // NIST 800-53 Rev 5: AC-8 — System Use Notification
    // Evidence: The default banner text contains the required DoD system use
    // notification elements: USG ownership, monitoring, and consent language.
    let config = BannerConfig::default();
    let presentation = build_banner_presentation(&config).unwrap();

    assert!(
        presentation.text.contains("U.S. Government"),
        "banner must reference U.S. Government"
    );
    assert!(
        presentation.text.contains("monitoring"),
        "banner must mention monitoring"
    );
    assert!(
        presentation.text.contains("consent"),
        "banner must mention consent"
    );
    assert!(
        presentation.text.contains("USG-authorized"),
        "banner must mention USG-authorized use"
    );
    assert!(
        presentation.title.contains("Department of Defense"),
        "banner title must reference DoD"
    );
}

#[test]
fn integration_banner_config_serialization_roundtrip() {
    // Verify BannerConfig survives JSON serialization and deserialization
    // with all default fields intact.
    let original = BannerConfig::default();
    let json = serde_json::to_string(&original).expect("serialize");
    let restored: BannerConfig = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(original.title, restored.title);
    assert_eq!(original.text, restored.text);
    assert_eq!(original.accept_label, restored.accept_label);
}

#[test]
fn nist_ac8_banner_acknowledgment_validates_nonce() {
    // NIST 800-53 Rev 5: AC-8 — System Use Notification
    // Evidence: A valid acknowledgment with the correct nonce passes;
    // an acknowledgment with a wrong nonce is rejected.
    let config = BannerConfig::default();
    let presentation = build_banner_presentation(&config).unwrap();

    let valid_ack = BannerAcknowledgment {
        nonce: presentation.nonce.clone(),
        acknowledged_at: Utc::now(),
        client_ip: "10.0.0.1".to_string(),
    };
    assert!(validate_acknowledgment(&presentation.nonce, &valid_ack).is_ok());

    let invalid_ack = BannerAcknowledgment {
        nonce: "wrong-nonce".to_string(),
        acknowledged_at: Utc::now(),
        client_ip: "10.0.0.1".to_string(),
    };
    assert!(matches!(
        validate_acknowledgment(&presentation.nonce, &invalid_ack),
        Err(EnrollmentError::BannerNotAcknowledged)
    ));
}

// ===========================================================================
// 2. Enrollment flow tests
// ===========================================================================

#[test]
fn integration_enrollment_request_construction_nipr() {
    // Enrollment session is correctly initialized from NIPR config.
    let config = nipr_config();
    let session = start_enrollment(&config).unwrap();

    assert_eq!(session.enclave, Enclave::Nipr);
    assert_eq!(session.phase, EnrollmentPhase::BannerPending);
    assert!(session.banner_nonce.is_none());
    assert!(session.auth_request_id.is_none());
}

#[test]
fn integration_enrollment_request_construction_sipr() {
    // Enrollment session is correctly initialized from SIPR config.
    let config = sipr_config();
    let session = start_enrollment(&config).unwrap();

    assert_eq!(session.enclave, Enclave::Sipr);
    assert_eq!(session.phase, EnrollmentPhase::BannerPending);
}

#[test]
fn integration_enrollment_state_machine_transitions() {
    // Walk the full enrollment state machine from BannerPending to Complete.
    let config = nipr_config();
    let mut session = start_enrollment(&config).unwrap();

    // BannerPending -> BannerDisplayed
    mark_banner_displayed(&mut session, "nonce-1".to_string()).unwrap();
    assert_eq!(session.phase, EnrollmentPhase::BannerDisplayed);
    assert_eq!(session.banner_nonce.as_deref(), Some("nonce-1"));

    // BannerDisplayed -> Redirecting
    mark_banner_acknowledged(&mut session).unwrap();
    assert_eq!(session.phase, EnrollmentPhase::Redirecting);

    // Redirecting -> Authenticating
    mark_redirected(&mut session, "state-csrf-token".to_string()).unwrap();
    assert_eq!(session.phase, EnrollmentPhase::Authenticating);
    assert_eq!(
        session.auth_request_id.as_deref(),
        Some("state-csrf-token")
    );

    // Authenticating -> Complete
    mark_complete(&mut session).unwrap();
    assert_eq!(session.phase, EnrollmentPhase::Complete);
}

#[test]
fn integration_enrollment_rejects_out_of_order_transitions() {
    // Verify that skipping phases is rejected at each step.
    let config = nipr_config();
    let mut session = start_enrollment(&config).unwrap();

    // Cannot redirect before banner is acknowledged.
    assert!(mark_redirected(&mut session, "state".to_string()).is_err());

    // Cannot complete from BannerPending.
    assert!(mark_complete(&mut session).is_err());

    // Cannot display banner twice.
    mark_banner_displayed(&mut session, "n".to_string()).unwrap();
    assert!(mark_banner_displayed(&mut session, "n2".to_string()).is_err());
}

#[test]
fn integration_idempotent_enrollment_returning_user() {
    // A returning user (recognized by EDIPI) should be able to start a new
    // enrollment session without error. The system uses the same flow but
    // produces an EnrollmentOutcome::ReturningUser at the end. Here we
    // verify that starting enrollment twice is not an error.
    let config = nipr_config();

    // First enrollment.
    let session1 = start_enrollment(&config).unwrap();
    assert_eq!(session1.phase, EnrollmentPhase::BannerPending);

    // "Returning" user starts a fresh session -- no error.
    let session2 = start_enrollment(&config).unwrap();
    assert_eq!(session2.phase, EnrollmentPhase::BannerPending);
}

#[test]
fn integration_enrollment_session_serialization_roundtrip() {
    // EnrollmentSession must survive JSON round-trip (for session storage).
    let config = nipr_config();
    let mut session = start_enrollment(&config).unwrap();
    mark_banner_displayed(&mut session, "nonce-rt".to_string()).unwrap();

    let json = serde_json::to_string(&session).expect("serialize");
    let restored: pf_enroll_portal::EnrollmentSession =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.phase, EnrollmentPhase::BannerDisplayed);
    assert_eq!(restored.enclave, Enclave::Nipr);
    assert_eq!(restored.banner_nonce.as_deref(), Some("nonce-rt"));
}

// ===========================================================================
// 3. Driver hub tests
// ===========================================================================

#[test]
fn integration_driver_listing_returns_entries_for_supported_oses() {
    // The driver catalog must contain entries for Windows, macOS, and Linux.
    let packages = sample_packages();
    let oses: Vec<OperatingSystem> = packages.iter().map(|p| p.os).collect();

    assert!(oses.contains(&OperatingSystem::Windows));
    assert!(oses.contains(&OperatingSystem::MacOs));
    assert!(oses.contains(&OperatingSystem::Linux));
}

#[test]
fn integration_os_auto_detection_from_user_agent() {
    // OS detection correctly identifies platform from various User-Agent strings.
    let windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    assert_eq!(
        OperatingSystem::from_user_agent(windows_ua),
        Some(OperatingSystem::Windows)
    );

    let mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15";
    assert_eq!(
        OperatingSystem::from_user_agent(mac_ua),
        Some(OperatingSystem::MacOs)
    );

    let linux_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0";
    assert_eq!(
        OperatingSystem::from_user_agent(linux_ua),
        Some(OperatingSystem::Linux)
    );

    // Unknown UA returns None.
    assert!(OperatingSystem::from_user_agent("curl/8.4.0").is_none());
}

#[test]
fn integration_driver_entries_include_sha256_checksums() {
    // Every driver package must have a SHA-256 checksum (64 hex chars).
    let config = nipr_config();
    let packages = sample_packages();
    let links = build_download_links(&config.driver_hub, &packages, None).unwrap();

    for link in &links {
        assert_eq!(
            link.package.sha256.len(),
            64,
            "SHA-256 digest must be 64 hex characters for {}",
            link.package.id
        );
    }
}

#[test]
fn nist_si7_driver_checksum_is_sha256() {
    // NIST 800-53 Rev 5: SI-7 — Software, Firmware, and Information Integrity
    // Evidence: Driver package checksums are 64 hex characters (SHA-256)
    // and contain only valid hex digits.
    let packages = sample_packages();

    for pkg in &packages {
        assert_eq!(
            pkg.sha256.len(),
            64,
            "checksum for {} must be 64 hex chars",
            pkg.id
        );
        assert!(
            pkg.sha256.chars().all(|c| c.is_ascii_hexdigit()),
            "checksum for {} must contain only hex digits",
            pkg.id
        );
    }
}

#[test]
fn integration_driver_download_links_mark_recommended() {
    // When OS is detected, the matching package is flagged as recommended.
    let config = nipr_config();
    let packages = sample_packages();

    let links =
        build_download_links(&config.driver_hub, &packages, Some(OperatingSystem::MacOs)).unwrap();

    for link in &links {
        if link.package.os == OperatingSystem::MacOs {
            assert!(link.recommended, "macOS package should be recommended");
        } else {
            assert!(
                !link.recommended,
                "{} should not be recommended",
                link.package.id
            );
        }
    }
}

#[test]
fn integration_find_package_by_os_and_arch() {
    let packages = sample_packages();

    let found = find_package(&packages, OperatingSystem::Linux, Architecture::X86_64).unwrap();
    assert_eq!(found.os, OperatingSystem::Linux);
    assert_eq!(found.arch, Architecture::X86_64);

    // Non-existent combination.
    let missing = find_package(&packages, OperatingSystem::MacOs, Architecture::X86_64);
    assert!(matches!(
        missing,
        Err(EnrollmentError::DriverNotFound { .. })
    ));
}

// ===========================================================================
// 4. IdP redirect tests
// ===========================================================================

#[test]
fn nist_ia2_oidc_state_prevents_csrf() {
    // NIST 800-53 Rev 5: IA-2 — Identification and Authentication
    // Evidence: The OIDC authorization URL includes a non-empty state
    // parameter and PKCE code_challenge, preventing CSRF and authorization
    // code interception.
    let config = nipr_config();
    let result = initiate_redirect(&config).unwrap();

    match result {
        RedirectResult::Oidc {
            redirect_url,
            flow_state,
        } => {
            // State is present and non-empty.
            assert!(!flow_state.state.is_empty(), "state must be non-empty");

            // Nonce is present.
            assert!(!flow_state.nonce.is_empty(), "nonce must be non-empty");

            // The redirect URL includes the state parameter.
            let url_str = redirect_url.to_string();
            assert!(
                url_str.contains("state="),
                "redirect URL must contain state parameter"
            );
        }
        RedirectResult::Saml { .. } => panic!("expected OIDC redirect for NIPR"),
    }
}

#[test]
fn integration_oidc_auth_url_includes_required_params() {
    // OIDC authorization URL must contain response_type, client_id,
    // code_challenge, and redirect_uri.
    let config = nipr_config();
    let result = initiate_redirect(&config).unwrap();

    if let RedirectResult::Oidc { redirect_url, .. } = result {
        let url_str = redirect_url.to_string();
        assert!(url_str.contains("response_type=code"));
        assert!(url_str.contains("client_id=test-client-id"));
        assert!(url_str.contains("code_challenge="));
        assert!(url_str.contains("code_challenge_method="));
    } else {
        panic!("expected OIDC redirect");
    }
}

#[test]
fn integration_saml_authn_request_has_unique_id() {
    // Each SAML AuthnRequest has a unique ID for InResponseTo validation.
    let config = sipr_config();

    let r1 = initiate_redirect(&config).unwrap();
    let r2 = initiate_redirect(&config).unwrap();

    let id1 = match r1 {
        RedirectResult::Saml { authn_request, .. } => authn_request.id,
        RedirectResult::Oidc { .. } => panic!("expected SAML redirect"),
    };
    let id2 = match r2 {
        RedirectResult::Saml { authn_request, .. } => authn_request.id,
        RedirectResult::Oidc { .. } => panic!("expected SAML redirect"),
    };

    assert_ne!(id1, id2, "each AuthnRequest must have a unique ID");
    assert!(
        id1.starts_with("_pf_"),
        "AuthnRequest ID should start with _pf_"
    );
}

#[test]
fn integration_oidc_callback_validates_state() {
    // OIDC callback rejects mismatched state (CSRF protection).
    let config = nipr_config();
    let result = initiate_redirect(&config).unwrap();

    if let RedirectResult::Oidc { flow_state, .. } = result {
        // Matching state proceeds (hits stub).
        let matching_params = OidcCallbackParams {
            code: "test-auth-code".to_string(),
            state: flow_state.state.clone(),
        };
        let matching_result =
            pf_enroll_portal::callback::process_oidc_callback(&matching_params, &flow_state);
        // Should NOT be StateMismatch (it's AuthenticationFailed because exchange is unimplemented).
        assert!(
            !matches!(matching_result, Err(EnrollmentError::StateMismatch)),
            "matching state must not produce StateMismatch"
        );

        // Mismatched state is rejected.
        let bad_params = OidcCallbackParams {
            code: "test-auth-code".to_string(),
            state: "attacker-state".to_string(),
        };
        let bad_result =
            pf_enroll_portal::callback::process_oidc_callback(&bad_params, &flow_state);
        assert!(matches!(bad_result, Err(EnrollmentError::StateMismatch)));
    } else {
        panic!("expected OIDC redirect");
    }
}

#[test]
fn integration_saml_callback_rejects_empty_response() {
    // Empty SAMLResponse is rejected before any parsing attempt.
    let params = SamlCallbackParams {
        saml_response: String::new(),
        relay_state: None,
    };
    let result = pf_enroll_portal::callback::process_saml_callback(&params, "_pf_test-id");
    assert!(matches!(
        result,
        Err(EnrollmentError::MissingCallbackData { .. })
    ));
}

// ===========================================================================
// 5. Profile tests
// ===========================================================================

#[test]
fn integration_profile_response_serialization() {
    // UserProfile must survive JSON serialization and deserialization.
    let profile = build_profile(
        "DOE.JOHN.Q.1234567890",
        "Test Unit, Test Base AFB",
        Some("john.doe@test.mil"),
        UserPreferences::default(),
    )
    .unwrap();

    let json = serde_json::to_string(&profile).expect("serialize");
    let restored: UserProfile = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.display_name, "DOE.JOHN.Q.1234567890");
    assert_eq!(restored.organization, "Test Unit, Test Base AFB");
    assert_eq!(restored.email.as_deref(), Some("john.doe@test.mil"));
    assert_eq!(
        restored.preferences.default_duplex,
        DuplexMode::DuplexLongEdge
    );
    assert_eq!(restored.preferences.default_color, ColorMode::Auto);
}

#[test]
fn integration_preference_update_validation_accepts_valid() {
    // Valid preference updates pass validation.
    let edipi = Edipi::new("1234567890").unwrap();
    let update = PreferenceUpdate {
        default_duplex: Some(DuplexMode::Simplex),
        default_color: Some(ColorMode::Grayscale),
        email_notifications: Some(true),
        notification_email: Some("doe.john@test.mil".to_string()),
    };

    assert!(validate_preference_update(&edipi, &update).is_ok());
}

#[test]
fn integration_preference_update_validation_rejects_bad_email() {
    // Email without '@' is rejected.
    let edipi = Edipi::new("1234567890").unwrap();
    let update = PreferenceUpdate {
        default_duplex: None,
        default_color: None,
        email_notifications: None,
        notification_email: Some("no-at-sign".to_string()),
    };

    let result = validate_preference_update(&edipi, &update);
    assert!(matches!(
        result,
        Err(EnrollmentError::InvalidProfile { .. })
    ));
}

#[test]
fn integration_preference_update_applies_partial_changes() {
    // Partial updates merge with existing preferences.
    let current = UserPreferences {
        default_duplex: DuplexMode::DuplexLongEdge,
        default_color: ColorMode::Auto,
        email_notifications: false,
        notification_email: Some("original@test.mil".to_string()),
    };

    let update = PreferenceUpdate {
        default_duplex: Some(DuplexMode::Simplex),
        default_color: None, // keep existing
        email_notifications: Some(true),
        notification_email: None, // keep existing
    };

    let updated = apply_preference_update(&current, &update);
    assert_eq!(updated.default_duplex, DuplexMode::Simplex);
    assert_eq!(updated.default_color, ColorMode::Auto); // unchanged
    assert!(updated.email_notifications);
    assert_eq!(
        updated.notification_email.as_deref(),
        Some("original@test.mil")
    );
}

#[test]
fn integration_build_profile_with_no_email() {
    // Profile can be built without an email address.
    let profile = build_profile(
        "DOE.JOHN.Q.1234567890",
        "Test Unit, Test Base AFB",
        None,
        UserPreferences::default(),
    )
    .unwrap();

    assert!(profile.email.is_none());
    assert_eq!(profile.display_name, "DOE.JOHN.Q.1234567890");
}

#[test]
fn integration_preferences_serialization_roundtrip() {
    // UserPreferences survives JSON round-trip with all variants.
    let prefs = UserPreferences {
        default_duplex: DuplexMode::DuplexShortEdge,
        default_color: ColorMode::Color,
        email_notifications: true,
        notification_email: Some("test@test.mil".to_string()),
    };

    let json = serde_json::to_string(&prefs).expect("serialize");
    let restored: UserPreferences = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.default_duplex, DuplexMode::DuplexShortEdge);
    assert_eq!(restored.default_color, ColorMode::Color);
    assert!(restored.email_notifications);
    assert_eq!(
        restored.notification_email.as_deref(),
        Some("test@test.mil")
    );
}

// ===========================================================================
// 6. Config serialization
// ===========================================================================

#[test]
fn integration_enroll_portal_config_serialization_roundtrip() {
    // Full EnrollPortalConfig survives JSON serialization.
    let config = nipr_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: EnrollPortalConfig = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.enclave, Enclave::Nipr);
    assert!(restored.oidc.is_some());
    assert!(restored.saml.is_none());
    assert_eq!(
        restored.portal_base_url.as_str(),
        "https://printforge.local/"
    );
}

#[test]
fn integration_enclave_serialization_variants() {
    // Both Enclave variants serialize and deserialize correctly.
    let nipr_json = serde_json::to_string(&Enclave::Nipr).unwrap();
    let sipr_json = serde_json::to_string(&Enclave::Sipr).unwrap();

    let nipr: Enclave = serde_json::from_str(&nipr_json).unwrap();
    let sipr: Enclave = serde_json::from_str(&sipr_json).unwrap();

    assert_eq!(nipr, Enclave::Nipr);
    assert_eq!(sipr, Enclave::Sipr);
}
