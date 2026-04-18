// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Cost center assignment from `IdP` claims.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! Extracts cost center information from normalized claims and validates
//! it against `PrintForge` requirements. Supports both `IdP`-provided cost
//! centers and user overrides (when permitted by policy).

use pf_common::job::CostCenter;

use crate::claims::NormalizedClaims;
use crate::error::ProvisioningError;

/// Extract and validate a [`CostCenter`] from normalized claims.
///
/// Returns `None` if the claims do not contain cost center information.
///
/// # Errors
///
/// Returns `ProvisioningError::InvalidCostCenter` if the cost center code
/// is present but fails validation.
pub fn extract_cost_center(
    claims: &NormalizedClaims,
) -> Result<Option<CostCenter>, ProvisioningError> {
    let Some(code) = claims.cost_center_code.as_deref() else {
        return Ok(None);
    };

    if code.trim().is_empty() {
        return Ok(None);
    }

    let name = claims.cost_center_name.as_deref().unwrap_or("");

    let cost_center = CostCenter::new(code, name).map_err(ProvisioningError::InvalidCostCenter)?;

    Ok(Some(cost_center))
}

/// Merge `IdP`-provided cost centers with the user's existing cost centers.
///
/// If the `IdP` provides a cost center that already exists in the user's list,
/// it is updated. New cost centers are appended.
#[must_use]
pub fn merge_cost_centers(
    existing: &[CostCenter],
    from_claims: Option<&CostCenter>,
) -> Vec<CostCenter> {
    let mut result: Vec<CostCenter> = existing.to_vec();

    if let Some(new_cc) = from_claims {
        // Replace if same code, otherwise append.
        if let Some(existing_cc) = result.iter_mut().find(|cc| cc.code == new_cc.code) {
            existing_cc.name.clone_from(&new_cc.name);
        } else {
            result.push(new_cc.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsSource;
    use std::collections::HashMap;

    fn claims_with_cost_center(code: &str, name: &str) -> NormalizedClaims {
        NormalizedClaims {
            edipi_raw: "1234567890".to_string(),
            display_name: None,
            organization: None,
            email: None,
            groups: Vec::new(),
            cost_center_code: Some(code.to_string()),
            cost_center_name: Some(name.to_string()),
            source: ClaimsSource::Oidc,
            extra: HashMap::new(),
        }
    }

    fn claims_without_cost_center() -> NormalizedClaims {
        NormalizedClaims {
            edipi_raw: "1234567890".to_string(),
            display_name: None,
            organization: None,
            email: None,
            groups: Vec::new(),
            cost_center_code: None,
            cost_center_name: None,
            source: ClaimsSource::Oidc,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn extract_valid_cost_center() {
        let claims = claims_with_cost_center("CC001", "Test Squadron");
        let cc = extract_cost_center(&claims).unwrap();
        assert!(cc.is_some());
        let cc = cc.unwrap();
        assert_eq!(cc.code, "CC001");
        assert_eq!(cc.name, "Test Squadron");
    }

    #[test]
    fn extract_missing_cost_center_returns_none() {
        let claims = claims_without_cost_center();
        let cc = extract_cost_center(&claims).unwrap();
        assert!(cc.is_none());
    }

    #[test]
    fn extract_empty_cost_center_code_returns_none() {
        let claims = claims_with_cost_center("   ", "Blank Code");
        let cc = extract_cost_center(&claims).unwrap();
        assert!(cc.is_none());
    }

    #[test]
    fn merge_appends_new_cost_center() {
        let existing = vec![CostCenter::new("CC001", "First").unwrap()];
        let new_cc = CostCenter::new("CC002", "Second").unwrap();
        let result = merge_cost_centers(&existing, Some(&new_cc));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn merge_updates_existing_cost_center_name() {
        let existing = vec![CostCenter::new("CC001", "Old Name").unwrap()];
        let updated = CostCenter::new("CC001", "New Name").unwrap();
        let result = merge_cost_centers(&existing, Some(&updated));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "New Name");
    }

    #[test]
    fn merge_with_none_returns_existing() {
        let existing = vec![CostCenter::new("CC001", "Only One").unwrap()];
        let result = merge_cost_centers(&existing, None);
        assert_eq!(result.len(), 1);
    }
}
