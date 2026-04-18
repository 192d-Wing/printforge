// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Attribute synchronization between `IdP` claims and stored user records.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! On every login, incoming claims are compared against the stored user
//! record. Changed attributes (name, organization, cost center, roles)
//! are updated. This keeps `PrintForge` in sync with the `IdP` without
//! requiring a continuous sync pipeline.

use chrono::Utc;
use tracing::info;

use crate::claims::NormalizedClaims;
use crate::config::ProvisioningConfig;
use crate::cost_center::{extract_cost_center, merge_cost_centers};
use crate::error::ProvisioningError;
use crate::role_mapping::evaluate_role_mappings;
use crate::user::ProvisionedUser;

/// Individual attribute that may have changed during synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangedAttribute {
    /// The display name changed.
    DisplayName,
    /// The organization changed.
    Organization,
    /// The roles changed.
    Roles,
    /// The cost centers changed.
    CostCenters,
}

/// A record of which attributes changed during synchronization.
#[derive(Debug, Clone, Default)]
pub struct SyncChanges {
    /// The set of attributes that changed.
    pub changed: Vec<ChangedAttribute>,
}

impl SyncChanges {
    /// Returns `true` if any attribute changed.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.changed.is_empty()
    }

    /// Returns `true` if the given attribute changed.
    #[must_use]
    pub fn contains(&self, attr: ChangedAttribute) -> bool {
        self.changed.contains(&attr)
    }
}

/// Compare incoming claims against a stored user and return an updated user
/// with any changed attributes applied.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
///
/// # Errors
///
/// Returns `ProvisioningError::InvalidCostCenter` if the cost center in claims
/// fails validation.
pub fn sync_attributes(
    config: &ProvisioningConfig,
    mut user: ProvisionedUser,
    claims: &NormalizedClaims,
) -> Result<ProvisionedUser, ProvisioningError> {
    let changes = detect_changes(config, &user, claims)?;

    if !changes.has_changes() {
        // Update last login time even if no attributes changed.
        user.last_login_at = Some(Utc::now());
        user.updated_at = Utc::now();
        return Ok(user);
    }

    if changes.contains(ChangedAttribute::DisplayName) {
        if let Some(ref name) = claims.display_name {
            info!(
                old = %user.display_name,
                new = %name,
                "display name changed"
            );
            user.display_name.clone_from(name);
        }
    }

    if changes.contains(ChangedAttribute::Organization) {
        if let Some(ref org) = claims.organization {
            info!(
                old = %user.organization,
                new = %org,
                "organization changed"
            );
            user.organization.clone_from(org);
        }
    }

    if changes.contains(ChangedAttribute::Roles) {
        let role_result = evaluate_role_mappings(
            &config.role_mappings,
            &claims.groups,
            config.max_groups_per_user,
        );
        if !role_result.roles.is_empty() {
            info!("roles changed");
            user.roles = role_result.roles;
        }
    }

    if changes.contains(ChangedAttribute::CostCenters) {
        let new_cc = extract_cost_center(claims)?;
        user.cost_centers = merge_cost_centers(&user.cost_centers, new_cc.as_ref());
        info!("cost centers updated");
    }

    user.last_login_at = Some(Utc::now());
    user.updated_at = Utc::now();

    Ok(user)
}

/// Detect which attributes differ between the stored user and incoming claims.
fn detect_changes(
    config: &ProvisioningConfig,
    user: &ProvisionedUser,
    claims: &NormalizedClaims,
) -> Result<SyncChanges, ProvisioningError> {
    let mut changed = Vec::new();

    // Display name.
    if let Some(ref name) = claims.display_name {
        if *name != user.display_name {
            changed.push(ChangedAttribute::DisplayName);
        }
    }

    // Organization.
    if let Some(ref org) = claims.organization {
        if *org != user.organization {
            changed.push(ChangedAttribute::Organization);
        }
    }

    // Roles (re-evaluate from current group claims).
    let role_result = evaluate_role_mappings(
        &config.role_mappings,
        &claims.groups,
        config.max_groups_per_user,
    );
    if !role_result.roles.is_empty() && role_result.roles != user.roles {
        changed.push(ChangedAttribute::Roles);
    }

    // Cost centers.
    let new_cc = extract_cost_center(claims)?;
    if let Some(ref cc) = new_cc {
        let existing_codes: Vec<&str> = user.cost_centers.iter().map(|c| c.code.as_str()).collect();
        if !existing_codes.contains(&cc.code.as_str()) {
            changed.push(ChangedAttribute::CostCenters);
        } else if let Some(existing) = user.cost_centers.iter().find(|c| c.code == cc.code) {
            if existing.name != cc.name {
                changed.push(ChangedAttribute::CostCenters);
            }
        }
    }

    Ok(SyncChanges { changed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsSource;
    use crate::role_mapping::RoleMappingRule;
    use crate::user::{ProvisioningSource, UserPreferences, UserStatus};
    use chrono::Utc;
    use pf_common::identity::{Edipi, Role};
    use pf_common::job::CostCenter;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn test_config() -> ProvisioningConfig {
        ProvisioningConfig {
            role_mappings: vec![
                RoleMappingRule {
                    group_pattern: "PrintForge-Users".to_string(),
                    target_role: "User".to_string(),
                },
                RoleMappingRule {
                    group_pattern: "PrintForge-FleetAdmin".to_string(),
                    target_role: "FleetAdmin".to_string(),
                },
            ],
            ..ProvisioningConfig::default()
        }
    }

    fn test_user() -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new("1234567890").unwrap(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "42 CS, Maxwell AFB".to_string(),
            roles: vec![Role::User],
            cost_centers: vec![CostCenter::new("CC001", "Test Squadron").unwrap()],
            preferences: UserPreferences::default(),
            status: UserStatus::Active,
            provisioning_source: ProvisioningSource::Jit,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        }
    }

    fn test_claims() -> NormalizedClaims {
        NormalizedClaims {
            edipi_raw: "1234567890".to_string(),
            display_name: Some("DOE, JOHN Q.".to_string()),
            organization: Some("42 CS, Maxwell AFB".to_string()),
            email: None,
            groups: vec!["PrintForge-Users".to_string()],
            cost_center_code: Some("CC001".to_string()),
            cost_center_name: Some("Test Squadron".to_string()),
            source: ClaimsSource::Oidc,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn no_changes_when_claims_match() {
        let config = test_config();
        let user = test_user();
        let claims = test_claims();

        let updated = sync_attributes(&config, user.clone(), &claims).unwrap();
        assert_eq!(updated.display_name, user.display_name);
        assert_eq!(updated.organization, user.organization);
    }

    #[test]
    fn syncs_changed_display_name() {
        let config = test_config();
        let user = test_user();
        let mut claims = test_claims();
        claims.display_name = Some("DOE, JOHN Q. JR.".to_string());

        let updated = sync_attributes(&config, user, &claims).unwrap();
        assert_eq!(updated.display_name, "DOE, JOHN Q. JR.");
    }

    #[test]
    fn syncs_changed_organization() {
        let config = test_config();
        let user = test_user();
        let mut claims = test_claims();
        claims.organization = Some("99 CS, Offutt AFB".to_string());

        let updated = sync_attributes(&config, user, &claims).unwrap();
        assert_eq!(updated.organization, "99 CS, Offutt AFB");
    }

    #[test]
    fn syncs_changed_roles() {
        let config = test_config();
        let user = test_user();
        let mut claims = test_claims();
        claims.groups = vec![
            "PrintForge-Users".to_string(),
            "PrintForge-FleetAdmin".to_string(),
        ];

        let updated = sync_attributes(&config, user, &claims).unwrap();
        assert!(updated.roles.contains(&Role::User));
        assert!(updated.roles.contains(&Role::FleetAdmin));
    }

    #[test]
    fn syncs_new_cost_center() {
        let config = test_config();
        let user = test_user();
        let mut claims = test_claims();
        claims.cost_center_code = Some("CC002".to_string());
        claims.cost_center_name = Some("New Squadron".to_string());

        let updated = sync_attributes(&config, user, &claims).unwrap();
        assert_eq!(updated.cost_centers.len(), 2);
    }

    #[test]
    fn updates_last_login_even_without_changes() {
        let config = test_config();
        let user = test_user();
        let claims = test_claims();

        let updated = sync_attributes(&config, user, &claims).unwrap();
        assert!(updated.last_login_at.is_some());
    }

    #[test]
    fn nist_ac2_attribute_sync_updates_on_login() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Attribute sync detects and applies changes from IdP claims
        // on every login, keeping the user record in sync with the IdP.
        let config = test_config();
        let user = test_user();
        let mut claims = test_claims();
        claims.display_name = Some("SMITH, JANE A.".to_string());
        claims.organization = Some("New Org".to_string());

        let updated = sync_attributes(&config, user, &claims).unwrap();
        assert_eq!(updated.display_name, "SMITH, JANE A.");
        assert_eq!(updated.organization, "New Org");
    }
}
