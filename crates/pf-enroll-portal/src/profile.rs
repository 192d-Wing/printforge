// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Post-enrollment profile confirmation and preference editing.
//!
//! After successful enrollment (or on returning-user login), users can
//! review their profile information and update preferences such as
//! default printer, duplex mode, and notification settings.

use pf_common::identity::Edipi;
use serde::{Deserialize, Serialize};

use crate::error::EnrollmentError;

/// Maximum length for a display name.
const MAX_DISPLAY_NAME_LEN: usize = 256;

/// Maximum length for a notification email address.
const MAX_EMAIL_LEN: usize = 320;

/// User profile as displayed on the enrollment confirmation page.
///
/// These fields are sourced from the `IdP` claims and cannot be edited
/// directly (they sync on each login). Preferences are editable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// The user's display name (from `IdP`).
    pub display_name: String,
    /// The user's organization (from `IdP`).
    pub organization: String,
    /// Email address (from `IdP`).
    pub email: Option<String>,
    /// User-editable preferences.
    pub preferences: UserPreferences,
}

/// User-editable print preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    /// Default duplex mode.
    pub default_duplex: DuplexMode,
    /// Default color mode.
    pub default_color: ColorMode,
    /// Whether to receive email notifications for completed print jobs.
    pub email_notifications: bool,
    /// Preferred notification email (may differ from `IdP`-provided email).
    pub notification_email: Option<String>,
}

/// Duplex printing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DuplexMode {
    /// Single-sided printing.
    Simplex,
    /// Double-sided, long-edge binding.
    DuplexLongEdge,
    /// Double-sided, short-edge binding.
    DuplexShortEdge,
}

/// Color mode for print jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColorMode {
    /// Grayscale only.
    Grayscale,
    /// Full color.
    Color,
    /// Auto-detect from document content.
    Auto,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            default_duplex: DuplexMode::DuplexLongEdge,
            default_color: ColorMode::Auto,
            email_notifications: false,
            notification_email: None,
        }
    }
}

/// A validated request to update user preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceUpdate {
    /// New default duplex mode.
    pub default_duplex: Option<DuplexMode>,
    /// New default color mode.
    pub default_color: Option<ColorMode>,
    /// Whether to receive email notifications.
    pub email_notifications: Option<bool>,
    /// Preferred notification email address.
    pub notification_email: Option<String>,
}

/// Validate a preference update request.
///
/// **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
///
/// # Errors
///
/// Returns `EnrollmentError::InvalidProfile` if any field fails validation
/// (e.g., email too long or malformed).
pub fn validate_preference_update(
    _edipi: &Edipi,
    update: &PreferenceUpdate,
) -> Result<(), EnrollmentError> {
    if let Some(email) = &update.notification_email {
        let trimmed = email.trim();
        if trimmed.len() > MAX_EMAIL_LEN {
            return Err(EnrollmentError::InvalidProfile {
                detail: format!("notification email exceeds maximum length of {MAX_EMAIL_LEN}"),
            });
        }
        if !trimmed.is_empty() && !trimmed.contains('@') {
            return Err(EnrollmentError::InvalidProfile {
                detail: "notification email must contain '@'".to_string(),
            });
        }
    }

    Ok(())
}

/// Apply a [`PreferenceUpdate`] to an existing [`UserPreferences`], returning
/// the updated preferences.
#[must_use]
pub fn apply_preference_update(
    current: &UserPreferences,
    update: &PreferenceUpdate,
) -> UserPreferences {
    UserPreferences {
        default_duplex: update.default_duplex.unwrap_or(current.default_duplex),
        default_color: update.default_color.unwrap_or(current.default_color),
        email_notifications: update
            .email_notifications
            .unwrap_or(current.email_notifications),
        notification_email: update
            .notification_email
            .clone()
            .or_else(|| current.notification_email.clone()),
    }
}

/// Build a [`UserProfile`] for the confirmation page from `IdP`-sourced data
/// and existing preferences.
///
/// # Errors
///
/// Returns `EnrollmentError::InvalidProfile` if the display name exceeds
/// the maximum length.
pub fn build_profile(
    display_name: &str,
    organization: &str,
    email: Option<&str>,
    preferences: UserPreferences,
) -> Result<UserProfile, EnrollmentError> {
    if display_name.len() > MAX_DISPLAY_NAME_LEN {
        return Err(EnrollmentError::InvalidProfile {
            detail: format!("display name exceeds maximum length of {MAX_DISPLAY_NAME_LEN}"),
        });
    }

    Ok(UserProfile {
        display_name: display_name.to_string(),
        organization: organization.to_string(),
        email: email.map(String::from),
        preferences,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences_favor_duplex_and_auto_color() {
        let prefs = UserPreferences::default();
        assert_eq!(prefs.default_duplex, DuplexMode::DuplexLongEdge);
        assert_eq!(prefs.default_color, ColorMode::Auto);
        assert!(!prefs.email_notifications);
    }

    #[test]
    fn validate_preference_update_accepts_valid_email() {
        let edipi = Edipi::new("1234567890").unwrap();
        let update = PreferenceUpdate {
            default_duplex: None,
            default_color: None,
            email_notifications: Some(true),
            notification_email: Some("john.doe@test.mil".to_string()),
        };

        assert!(validate_preference_update(&edipi, &update).is_ok());
    }

    #[test]
    fn validate_preference_update_rejects_email_without_at() {
        let edipi = Edipi::new("1234567890").unwrap();
        let update = PreferenceUpdate {
            default_duplex: None,
            default_color: None,
            email_notifications: None,
            notification_email: Some("not-an-email".to_string()),
        };

        let result = validate_preference_update(&edipi, &update);
        assert!(matches!(
            result,
            Err(EnrollmentError::InvalidProfile { .. })
        ));
    }

    #[test]
    fn validate_preference_update_rejects_overlong_email() {
        let edipi = Edipi::new("1234567890").unwrap();
        let long_email = format!("{}@test.mil", "a".repeat(MAX_EMAIL_LEN));
        let update = PreferenceUpdate {
            default_duplex: None,
            default_color: None,
            email_notifications: None,
            notification_email: Some(long_email),
        };

        let result = validate_preference_update(&edipi, &update);
        assert!(matches!(
            result,
            Err(EnrollmentError::InvalidProfile { .. })
        ));
    }

    #[test]
    fn validate_preference_update_allows_empty_email() {
        let edipi = Edipi::new("1234567890").unwrap();
        let update = PreferenceUpdate {
            default_duplex: None,
            default_color: None,
            email_notifications: None,
            notification_email: Some(String::new()),
        };

        assert!(validate_preference_update(&edipi, &update).is_ok());
    }

    #[test]
    fn apply_preference_update_merges_partial() {
        let current = UserPreferences::default();
        let update = PreferenceUpdate {
            default_duplex: Some(DuplexMode::Simplex),
            default_color: None,
            email_notifications: Some(true),
            notification_email: None,
        };

        let updated = apply_preference_update(&current, &update);
        assert_eq!(updated.default_duplex, DuplexMode::Simplex);
        assert_eq!(updated.default_color, ColorMode::Auto); // unchanged
        assert!(updated.email_notifications);
    }

    #[test]
    fn build_profile_creates_valid_profile() {
        let profile = build_profile(
            "DOE, JOHN Q.",
            "42 CS, Maxwell AFB",
            Some("john.doe@test.mil"),
            UserPreferences::default(),
        )
        .unwrap();

        assert_eq!(profile.display_name, "DOE, JOHN Q.");
        assert_eq!(profile.organization, "42 CS, Maxwell AFB");
        assert_eq!(profile.email.as_deref(), Some("john.doe@test.mil"));
    }

    #[test]
    fn build_profile_rejects_overlong_display_name() {
        let long_name = "A".repeat(MAX_DISPLAY_NAME_LEN + 1);
        let result = build_profile(&long_name, "Org", None, UserPreferences::default());
        assert!(matches!(
            result,
            Err(EnrollmentError::InvalidProfile { .. })
        ));
    }
}
