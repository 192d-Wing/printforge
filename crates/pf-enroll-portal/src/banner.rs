// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `DoD` consent/use notification banner (AC-8).
//!
//! **NIST 800-53 Rev 5:** AC-8 — System Use Notification
//!
//! The `DoD` consent banner MUST be displayed and explicitly acknowledged
//! by the user before any `IdP` redirect occurs. No user data is stored
//! before authentication; the acknowledgment is tracked as a client-side
//! token validated on the server before initiating the auth flow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::BannerConfig;
use crate::error::EnrollmentError;

/// A banner presentation containing the text to display to the user.
///
/// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerPresentation {
    /// Banner title.
    pub title: String,
    /// Full banner text body.
    pub text: String,
    /// Label for the acceptance button.
    pub accept_label: String,
    /// Unique nonce for this banner presentation (prevents replay).
    pub nonce: String,
}

/// A signed acknowledgment token proving the user accepted the banner.
///
/// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
///
/// This token is passed through the enrollment flow and validated before
/// the `IdP` redirect is initiated. It is short-lived and single-use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerAcknowledgment {
    /// The nonce from the [`BannerPresentation`] that was acknowledged.
    pub nonce: String,
    /// Timestamp when the user acknowledged the banner.
    pub acknowledged_at: DateTime<Utc>,
    /// IP address of the acknowledging client (for audit).
    pub client_ip: String,
}

/// Build a [`BannerPresentation`] from the configured banner text.
///
/// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
///
/// Generates a unique nonce for this presentation to prevent replay attacks.
///
/// # Errors
///
/// Returns `EnrollmentError::Internal` if nonce generation fails.
pub fn build_banner_presentation(
    config: &BannerConfig,
) -> Result<BannerPresentation, EnrollmentError> {
    let nonce_bytes = pf_common::crypto::random_bytes(16)
        .map_err(|e| EnrollmentError::Internal(format!("nonce generation failed: {e}")))?;
    let nonce = encode_hex(&nonce_bytes);

    Ok(BannerPresentation {
        title: config.title.clone(),
        text: config.text.clone(),
        accept_label: config.accept_label.clone(),
        nonce,
    })
}

/// Validate that a [`BannerAcknowledgment`] matches the expected nonce
/// and has not expired.
///
/// **NIST 800-53 Rev 5:** AC-8 — System Use Notification
///
/// # Errors
///
/// Returns `EnrollmentError::BannerNotAcknowledged` if the nonce does not
/// match or the acknowledgment has expired (older than 10 minutes).
pub fn validate_acknowledgment(
    expected_nonce: &str,
    ack: &BannerAcknowledgment,
) -> Result<(), EnrollmentError> {
    const MAX_AGE_SECONDS: i64 = 600;

    if ack.nonce != expected_nonce {
        tracing::warn!("banner acknowledgment nonce mismatch");
        return Err(EnrollmentError::BannerNotAcknowledged);
    }

    let age = Utc::now()
        .signed_duration_since(ack.acknowledged_at)
        .num_seconds();

    // Acknowledgments expire after 10 minutes.
    if !(0..=MAX_AGE_SECONDS).contains(&age) {
        tracing::warn!(
            age_seconds = age,
            "banner acknowledgment expired or future-dated"
        );
        return Err(EnrollmentError::BannerNotAcknowledged);
    }

    Ok(())
}

/// Encode a byte slice as a lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn test_banner_config() -> BannerConfig {
        BannerConfig::default()
    }

    #[test]
    fn nist_ac8_banner_presentation_includes_dod_text() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Banner presentation includes the DoD consent text.
        let config = test_banner_config();
        let presentation = build_banner_presentation(&config).unwrap();
        assert!(presentation.text.contains("U.S. Government"));
        assert!(presentation.text.contains("monitoring"));
        assert!(!presentation.nonce.is_empty());
    }

    #[test]
    fn nist_ac8_banner_nonce_is_unique() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Each banner presentation has a unique nonce.
        let config = test_banner_config();
        let p1 = build_banner_presentation(&config).unwrap();
        let p2 = build_banner_presentation(&config).unwrap();
        assert_ne!(p1.nonce, p2.nonce);
    }

    #[test]
    fn nist_ac8_valid_acknowledgment_passes() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: A valid acknowledgment with matching nonce passes validation.
        let config = test_banner_config();
        let presentation = build_banner_presentation(&config).unwrap();

        let ack = BannerAcknowledgment {
            nonce: presentation.nonce.clone(),
            acknowledged_at: Utc::now(),
            client_ip: "192.168.1.1".to_string(),
        };

        assert!(validate_acknowledgment(&presentation.nonce, &ack).is_ok());
    }

    #[test]
    fn nist_ac8_mismatched_nonce_rejected() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Mismatched nonce is rejected.
        let ack = BannerAcknowledgment {
            nonce: "wrong-nonce".to_string(),
            acknowledged_at: Utc::now(),
            client_ip: "192.168.1.1".to_string(),
        };

        let result = validate_acknowledgment("correct-nonce", &ack);
        assert!(matches!(
            result,
            Err(EnrollmentError::BannerNotAcknowledged)
        ));
    }

    #[test]
    fn nist_ac8_expired_acknowledgment_rejected() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Expired acknowledgment (>10 min) is rejected.
        let ack = BannerAcknowledgment {
            nonce: "test-nonce".to_string(),
            acknowledged_at: Utc::now() - Duration::minutes(15),
            client_ip: "192.168.1.1".to_string(),
        };

        let result = validate_acknowledgment("test-nonce", &ack);
        assert!(matches!(
            result,
            Err(EnrollmentError::BannerNotAcknowledged)
        ));
    }

    #[test]
    fn nist_ac8_future_dated_acknowledgment_rejected() {
        // NIST 800-53 Rev 5: AC-8 — System Use Notification
        // Evidence: Future-dated acknowledgment is rejected.
        let ack = BannerAcknowledgment {
            nonce: "test-nonce".to_string(),
            acknowledged_at: Utc::now() + Duration::hours(1),
            client_ip: "192.168.1.1".to_string(),
        };

        let result = validate_acknowledgment("test-nonce", &ack);
        assert!(matches!(
            result,
            Err(EnrollmentError::BannerNotAcknowledged)
        ));
    }
}
