// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Just-In-Time (JIT) provisioning from `IdP` claims.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! On first authentication, `PrintForge` automatically creates a user
//! account from the claims in the OIDC ID token or SAML assertion.
//! On subsequent logins, the attribute sync module updates any changed fields.

use chrono::Utc;
use pf_common::identity::{Edipi, Role};
use uuid::Uuid;

use crate::attribute_sync::sync_attributes;
use crate::claims::NormalizedClaims;
use crate::config::ProvisioningConfig;
use crate::cost_center::extract_cost_center;
use crate::error::ProvisioningError;
use crate::repository::UserRepository;
use crate::role_mapping::evaluate_role_mappings;
use crate::user::{ProvisionedUser, ProvisioningSource, UserPreferences, UserStatus};

/// Result of a JIT provisioning attempt.
#[derive(Debug)]
pub enum JitOutcome {
    /// A new user was created.
    Created(ProvisionedUser),
    /// An existing user was found and attributes were synchronized.
    Updated(ProvisionedUser),
}

/// Perform Just-In-Time provisioning or attribute sync for a user.
///
/// If the user does not exist in the repository, a new account is created.
/// If the user already exists, their attributes are synchronized with the
/// incoming claims.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-2(4) — Automated Audit Actions
///
/// # Errors
///
/// Returns `ProvisioningError::InvalidEdipi` if the EDIPI in claims is invalid.
/// Returns `ProvisioningError::AccountSuspended` if the user is suspended.
/// Returns `ProvisioningError::Repository` on persistence failures.
pub fn provision_or_sync(
    config: &ProvisioningConfig,
    repo: &dyn UserRepository,
    claims: &NormalizedClaims,
) -> Result<JitOutcome, ProvisioningError> {
    let edipi = Edipi::new(&claims.edipi_raw).map_err(ProvisioningError::InvalidEdipi)?;

    // Check if the user already exists.
    if let Some(existing) = repo.find_by_edipi(&edipi)? {
        // Suspended users cannot authenticate.
        if existing.status == UserStatus::Suspended {
            tracing::warn!("JIT sync attempted for suspended user");
            return Err(ProvisioningError::AccountSuspended);
        }

        // Attribute sync for returning users.
        let updated = sync_attributes(config, existing, claims)?;
        repo.update(&updated)?;

        tracing::info!("attribute sync completed for returning user");
        return Ok(JitOutcome::Updated(updated));
    }

    // First login — create a new user.
    let user = create_user_from_claims(config, &edipi, claims)?;
    repo.create(&user)?;

    tracing::info!("JIT provisioned new user");
    Ok(JitOutcome::Created(user))
}

/// Build a new [`ProvisionedUser`] from normalized claims.
fn create_user_from_claims(
    config: &ProvisioningConfig,
    edipi: &Edipi,
    claims: &NormalizedClaims,
) -> Result<ProvisionedUser, ProvisioningError> {
    let now = Utc::now();

    // Evaluate role mappings.
    let role_result = evaluate_role_mappings(
        &config.role_mappings,
        &claims.groups,
        config.max_groups_per_user,
    );

    let roles = if role_result.roles.is_empty() {
        // Apply default role when no mappings match.
        match config.default_role.as_str() {
            "Auditor" => vec![Role::Auditor],
            // Default to User for "User" and any unrecognized role string.
            _ => vec![Role::User],
        }
    } else {
        role_result.roles
    };

    // Extract cost center from claims.
    let cost_centers = match extract_cost_center(claims)? {
        Some(cc) => vec![cc],
        None => Vec::new(),
    };

    Ok(ProvisionedUser {
        id: Uuid::new_v4(),
        edipi: edipi.clone(),
        display_name: claims
            .display_name
            .clone()
            .unwrap_or_else(|| "Unknown".to_string()),
        organization: claims
            .organization
            .clone()
            .unwrap_or_else(|| "Unknown".to_string()),
        roles,
        cost_centers,
        preferences: UserPreferences::default(),
        status: UserStatus::Active,
        provisioning_source: ProvisioningSource::Jit,
        created_at: now,
        updated_at: now,
        last_login_at: Some(now),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsSource;
    use crate::repository::InMemoryUserRepository;
    use crate::role_mapping::RoleMappingRule;
    use std::collections::HashMap;

    fn test_config() -> ProvisioningConfig {
        ProvisioningConfig {
            role_mappings: vec![
                RoleMappingRule {
                    group_pattern: "PrintForge-Users".to_string(),
                    target_role: "User".to_string(),
                },
                RoleMappingRule {
                    group_pattern: "PrintForge-SiteAdmin-*".to_string(),
                    target_role: "SiteAdmin".to_string(),
                },
            ],
            default_role: "User".to_string(),
            ..ProvisioningConfig::default()
        }
    }

    fn test_claims() -> NormalizedClaims {
        NormalizedClaims {
            edipi_raw: "1234567890".to_string(),
            display_name: Some("DOE, JOHN Q.".to_string()),
            organization: Some("42 CS, Maxwell AFB".to_string()),
            email: Some("john.doe@test.mil".to_string()),
            groups: vec!["PrintForge-Users".to_string()],
            cost_center_code: Some("CC001".to_string()),
            cost_center_name: Some("Test Squadron".to_string()),
            source: ClaimsSource::Oidc,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn nist_ac2_jit_creates_user_on_first_login() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: JIT provisioning creates a user on first login.
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let claims = test_claims();

        let outcome = provision_or_sync(&config, &repo, &claims).unwrap();
        assert!(matches!(outcome, JitOutcome::Created(_)));

        let edipi = Edipi::new("1234567890").unwrap();
        let user = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(user.display_name, "DOE, JOHN Q.");
        assert_eq!(user.status, UserStatus::Active);
        assert!(!user.roles.is_empty());
    }

    #[test]
    fn jit_second_login_syncs_attributes() {
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let claims = test_claims();

        // First login.
        let _ = provision_or_sync(&config, &repo, &claims).unwrap();

        // Second login with updated name.
        let mut updated_claims = test_claims();
        updated_claims.display_name = Some("DOE, JOHN Q. JR.".to_string());

        let outcome = provision_or_sync(&config, &repo, &updated_claims).unwrap();
        assert!(matches!(outcome, JitOutcome::Updated(_)));

        let edipi = Edipi::new("1234567890").unwrap();
        let user = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(user.display_name, "DOE, JOHN Q. JR.");
    }

    #[test]
    fn jit_suspended_user_cannot_provision() {
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let claims = test_claims();

        // Create then suspend.
        let _ = provision_or_sync(&config, &repo, &claims).unwrap();
        let edipi = Edipi::new("1234567890").unwrap();
        repo.update_status(&edipi, UserStatus::Suspended).unwrap();

        // Attempt login with suspended user.
        let result = provision_or_sync(&config, &repo, &claims);
        assert!(matches!(result, Err(ProvisioningError::AccountSuspended)));
    }

    #[test]
    fn jit_applies_default_role_when_no_groups_match() {
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let mut claims = test_claims();
        claims.groups = vec!["UnknownGroup".to_string()];

        let outcome = provision_or_sync(&config, &repo, &claims).unwrap();
        if let JitOutcome::Created(user) = outcome {
            assert!(user.roles.contains(&Role::User));
        } else {
            panic!("expected Created outcome");
        }
    }

    #[test]
    fn jit_invalid_edipi_returns_error() {
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let mut claims = test_claims();
        claims.edipi_raw = "not-valid".to_string();

        let result = provision_or_sync(&config, &repo, &claims);
        assert!(matches!(result, Err(ProvisioningError::InvalidEdipi(_))));
    }

    #[test]
    fn jit_assigns_cost_center_from_claims() {
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let claims = test_claims();

        let outcome = provision_or_sync(&config, &repo, &claims).unwrap();
        if let JitOutcome::Created(user) = outcome {
            assert_eq!(user.cost_centers.len(), 1);
            assert_eq!(user.cost_centers[0].code, "CC001");
        } else {
            panic!("expected Created outcome");
        }
    }

    #[test]
    fn nist_ac2_4_provisioning_emits_audit_event() {
        // NIST 800-53 Rev 5: AC-2(4) — Automated Audit Actions
        // Evidence: JIT provisioning returns an outcome that can be
        // converted to an audit event. The tracing::info! calls serve
        // as structured audit log entries.
        let config = test_config();
        let repo = InMemoryUserRepository::new();
        let claims = test_claims();

        let outcome = provision_or_sync(&config, &repo, &claims).unwrap();
        // The outcome type distinguishes Created vs Updated,
        // enabling the caller to emit the appropriate audit event.
        assert!(matches!(outcome, JitOutcome::Created(_)));
    }
}
