// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Cost center assignment logic.
//!
//! Determines which cost center a print job is charged to. The assignment
//! follows a priority order:
//! 1. Project code override (if the user specifies a project code)
//! 2. User-selected override (if the user explicitly picks a cost center)
//! 3. Primary cost center from `IdP` claims (default)

use pf_common::identity::Edipi;
use pf_common::job::CostCenter;
use serde::{Deserialize, Serialize};

use crate::error::AccountingError;

/// The source of a cost center assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentSource {
    /// Assigned from `IdP` claims during authentication (default).
    IdpClaim,
    /// User explicitly selected this cost center at print time.
    UserOverride,
    /// Charged to a project code.
    ProjectCode,
}

/// A resolved cost center assignment for a user's print job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostCenterAssignment {
    /// The user whose job is being charged.
    pub edipi: Edipi,
    /// The resolved cost center.
    pub cost_center: CostCenter,
    /// How the cost center was determined.
    pub source: AssignmentSource,
    /// Optional project code when `source` is [`AssignmentSource::ProjectCode`].
    pub project_code: Option<String>,
}

/// A user's cost center profile: their primary cost center from `IdP` claims
/// plus any additional authorized cost centers they may select.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCostProfile {
    /// The user's EDIPI.
    pub edipi: Edipi,
    /// Primary cost center from `IdP` claims.
    pub primary: CostCenter,
    /// Additional cost centers the user is authorized to charge to.
    pub authorized_overrides: Vec<CostCenter>,
    /// Project codes the user is authorized to use.
    pub authorized_projects: Vec<ProjectCode>,
}

/// A validated project code for cost tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCode {
    /// The project code string.
    pub code: String,
    /// Human-readable project name.
    pub name: String,
    /// The cost center this project is billed to.
    pub cost_center: CostCenter,
}

/// Resolve the cost center assignment for a print job.
///
/// The resolution order is:
/// 1. If a `project_code` is provided and the user is authorized, use the project's
///    cost center.
/// 2. If a `cost_center_override` is provided and the user is authorized, use it.
/// 3. Otherwise, use the user's primary cost center from `IdP` claims.
///
/// # Errors
///
/// Returns [`AccountingError::CostCenterNotFound`] if a requested override or
/// project code is not in the user's authorized list.
pub fn resolve_cost_center(
    profile: &UserCostProfile,
    project_code: Option<&str>,
    cost_center_override: Option<&str>,
) -> Result<CostCenterAssignment, AccountingError> {
    // Priority 1: Project code
    if let Some(code) = project_code {
        let project = profile
            .authorized_projects
            .iter()
            .find(|p| p.code == code)
            .ok_or_else(|| AccountingError::CostCenterNotFound {
                code: code.to_string(),
            })?;

        return Ok(CostCenterAssignment {
            edipi: profile.edipi.clone(),
            cost_center: project.cost_center.clone(),
            source: AssignmentSource::ProjectCode,
            project_code: Some(code.to_string()),
        });
    }

    // Priority 2: User override
    if let Some(override_code) = cost_center_override {
        let cc = profile
            .authorized_overrides
            .iter()
            .find(|cc| cc.code == override_code)
            .ok_or_else(|| AccountingError::CostCenterNotFound {
                code: override_code.to_string(),
            })?;

        return Ok(CostCenterAssignment {
            edipi: profile.edipi.clone(),
            cost_center: cc.clone(),
            source: AssignmentSource::UserOverride,
            project_code: None,
        });
    }

    // Priority 3: Primary from IdP
    Ok(CostCenterAssignment {
        edipi: profile.edipi.clone(),
        cost_center: profile.primary.clone(),
        source: AssignmentSource::IdpClaim,
        project_code: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> UserCostProfile {
        UserCostProfile {
            edipi: Edipi::new("1234567890").unwrap(),
            primary: CostCenter::new("CC-100", "Primary Unit").unwrap(),
            authorized_overrides: vec![
                CostCenter::new("CC-200", "Secondary Unit").unwrap(),
                CostCenter::new("CC-300", "Tertiary Unit").unwrap(),
            ],
            authorized_projects: vec![ProjectCode {
                code: "PROJ-A".to_string(),
                name: "Project Alpha".to_string(),
                cost_center: CostCenter::new("CC-400", "Project Alpha Fund").unwrap(),
            }],
        }
    }

    #[test]
    fn resolves_primary_by_default() {
        let profile = test_profile();
        let assignment = resolve_cost_center(&profile, None, None).unwrap();

        assert_eq!(assignment.cost_center.code, "CC-100");
        assert_eq!(assignment.source, AssignmentSource::IdpClaim);
        assert!(assignment.project_code.is_none());
    }

    #[test]
    fn resolves_user_override() {
        let profile = test_profile();
        let assignment = resolve_cost_center(&profile, None, Some("CC-200")).unwrap();

        assert_eq!(assignment.cost_center.code, "CC-200");
        assert_eq!(assignment.source, AssignmentSource::UserOverride);
    }

    #[test]
    fn resolves_project_code() {
        let profile = test_profile();
        let assignment = resolve_cost_center(&profile, Some("PROJ-A"), None).unwrap();

        assert_eq!(assignment.cost_center.code, "CC-400");
        assert_eq!(assignment.source, AssignmentSource::ProjectCode);
        assert_eq!(assignment.project_code.as_deref(), Some("PROJ-A"));
    }

    #[test]
    fn project_code_takes_priority_over_override() {
        let profile = test_profile();
        let assignment = resolve_cost_center(&profile, Some("PROJ-A"), Some("CC-200")).unwrap();

        assert_eq!(assignment.source, AssignmentSource::ProjectCode);
        assert_eq!(assignment.cost_center.code, "CC-400");
    }

    #[test]
    fn unauthorized_override_returns_error() {
        let profile = test_profile();
        let result = resolve_cost_center(&profile, None, Some("CC-999"));
        assert!(result.is_err());
    }

    #[test]
    fn unauthorized_project_code_returns_error() {
        let profile = test_profile();
        let result = resolve_cost_center(&profile, Some("PROJ-Z"), None);
        assert!(result.is_err());
    }
}
