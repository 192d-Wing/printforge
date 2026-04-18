// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Approval workflow for supply reorders.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, AU-12 — Audit Generation
//!
//! Orders below a configurable dollar threshold are auto-approved.
//! Orders above that threshold route to a Site Admin or Fleet Admin
//! depending on value.

use chrono::{DateTime, Utc};
use pf_common::identity::{Edipi, Role};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ApprovalConfig;
use crate::error::SupplyError;

/// The required approval level for an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalLevel {
    /// Order is auto-approved (below dollar threshold).
    Auto,
    /// Requires approval from a Site Admin.
    SiteAdmin,
    /// Requires approval from a Fleet Admin.
    FleetAdmin,
}

/// The outcome of an approval decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// The order was approved.
    Approved {
        /// Who approved it (system EDIPI for auto-approval).
        approved_by: Edipi,
        /// When the decision was made.
        decided_at: DateTime<Utc>,
    },
    /// The order was rejected.
    Rejected {
        /// Who rejected it.
        rejected_by: Edipi,
        /// When the decision was made.
        decided_at: DateTime<Utc>,
        /// Optional reason for rejection.
        reason: Option<String>,
    },
}

/// An approval request awaiting decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier for the approval request.
    pub id: Uuid,
    /// The reorder this approval is for.
    pub reorder_id: Uuid,
    /// Estimated order value in cents.
    pub order_value_cents: u64,
    /// Required approval level.
    pub required_level: ApprovalLevel,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// The decision, once made.
    pub decision: Option<ApprovalDecision>,
}

/// Determine the required approval level for a given order value.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
#[must_use]
pub fn determine_approval_level(order_value_cents: u64, config: &ApprovalConfig) -> ApprovalLevel {
    if order_value_cents <= config.auto_approve_limit_cents {
        ApprovalLevel::Auto
    } else if order_value_cents <= config.site_admin_limit_cents {
        ApprovalLevel::SiteAdmin
    } else {
        ApprovalLevel::FleetAdmin
    }
}

/// Verify that the given role satisfies the required approval level.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
///
/// # Errors
///
/// Returns [`SupplyError::InsufficientApprovalAuthority`] if the role
/// does not meet the required approval level.
pub fn verify_approval_authority(
    role: &Role,
    required_level: ApprovalLevel,
    order_value_cents: u64,
) -> Result<(), SupplyError> {
    let authorized = match required_level {
        ApprovalLevel::Auto => true,
        ApprovalLevel::SiteAdmin => matches!(role, Role::SiteAdmin(_) | Role::FleetAdmin),
        ApprovalLevel::FleetAdmin => matches!(role, Role::FleetAdmin),
    };

    if authorized {
        Ok(())
    } else {
        Err(SupplyError::InsufficientApprovalAuthority { order_value_cents })
    }
}

/// Process an approval decision by an authorized approver.
///
/// **NIST 800-53 Rev 5:** AC-3, AU-12
///
/// # Errors
///
/// Returns [`SupplyError::InsufficientApprovalAuthority`] if the
/// approver's role does not meet the required level.
pub fn approve_order(
    request: &mut ApprovalRequest,
    approver_edipi: &Edipi,
    approver_role: &Role,
) -> Result<(), SupplyError> {
    verify_approval_authority(
        approver_role,
        request.required_level,
        request.order_value_cents,
    )?;

    request.decision = Some(ApprovalDecision::Approved {
        approved_by: approver_edipi.clone(),
        decided_at: Utc::now(),
    });

    Ok(())
}

/// Reject an order with an optional reason.
///
/// # Errors
///
/// Returns [`SupplyError::InsufficientApprovalAuthority`] if the
/// rejector's role does not meet the required level.
pub fn reject_order(
    request: &mut ApprovalRequest,
    rejector_edipi: &Edipi,
    rejector_role: &Role,
    reason: Option<String>,
) -> Result<(), SupplyError> {
    verify_approval_authority(
        rejector_role,
        request.required_level,
        request.order_value_cents,
    )?;

    request.decision = Some(ApprovalDecision::Rejected {
        rejected_by: rejector_edipi.clone(),
        decided_at: Utc::now(),
        reason,
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::identity::SiteId;

    fn test_edipi() -> Edipi {
        Edipi::new("1234567890").unwrap()
    }

    fn site_admin_role() -> Role {
        Role::SiteAdmin(SiteId("TEST-BASE".to_string()))
    }

    fn make_request(value_cents: u64, level: ApprovalLevel) -> ApprovalRequest {
        ApprovalRequest {
            id: Uuid::now_v7(),
            reorder_id: Uuid::now_v7(),
            order_value_cents: value_cents,
            required_level: level,
            created_at: Utc::now(),
            decision: None,
        }
    }

    #[test]
    fn auto_approve_below_threshold() {
        let config = ApprovalConfig::default();
        let level = determine_approval_level(30_000, &config); // $300
        assert_eq!(level, ApprovalLevel::Auto);
    }

    #[test]
    fn site_admin_required_above_auto_threshold() {
        let config = ApprovalConfig::default();
        let level = determine_approval_level(100_000, &config); // $1,000
        assert_eq!(level, ApprovalLevel::SiteAdmin);
    }

    #[test]
    fn fleet_admin_required_for_large_orders() {
        let config = ApprovalConfig::default();
        let level = determine_approval_level(1_000_000, &config); // $10,000
        assert_eq!(level, ApprovalLevel::FleetAdmin);
    }

    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    #[test]
    fn nist_ac3_site_admin_cannot_approve_fleet_level_order() {
        let result =
            verify_approval_authority(&site_admin_role(), ApprovalLevel::FleetAdmin, 1_000_000);
        assert!(result.is_err());
    }

    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    #[test]
    fn nist_ac3_fleet_admin_can_approve_any_level() {
        assert!(verify_approval_authority(&Role::FleetAdmin, ApprovalLevel::Auto, 100).is_ok());
        assert!(
            verify_approval_authority(&Role::FleetAdmin, ApprovalLevel::SiteAdmin, 100_000).is_ok()
        );
        assert!(
            verify_approval_authority(&Role::FleetAdmin, ApprovalLevel::FleetAdmin, 1_000_000)
                .is_ok()
        );
    }

    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    #[test]
    fn nist_ac3_site_admin_can_approve_site_level() {
        assert!(
            verify_approval_authority(&site_admin_role(), ApprovalLevel::SiteAdmin, 100_000)
                .is_ok()
        );
    }

    #[test]
    fn approve_order_sets_decision() {
        let mut req = make_request(30_000, ApprovalLevel::SiteAdmin);
        approve_order(&mut req, &test_edipi(), &site_admin_role()).unwrap();
        assert!(matches!(
            req.decision,
            Some(ApprovalDecision::Approved { .. })
        ));
    }

    #[test]
    fn reject_order_sets_decision_with_reason() {
        let mut req = make_request(30_000, ApprovalLevel::SiteAdmin);
        reject_order(
            &mut req,
            &test_edipi(),
            &site_admin_role(),
            Some("Budget exhausted".to_string()),
        )
        .unwrap();
        match req.decision {
            Some(ApprovalDecision::Rejected { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("Budget exhausted"));
            }
            _ => panic!("expected Rejected decision"),
        }
    }
}
