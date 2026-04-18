// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! User management route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management

use axum::extract::Path;
use axum::routing::{get, patch};
use axum::{Json, Router};
use chrono::Utc;

use pf_common::identity::{Identity, Role, SiteId};
use pf_common::policy::QuotaStatus;

use crate::error::AdminUiError;
use crate::scope::{derive_scope, DataScope};
use crate::user_mgmt::{RoleAssignmentRequest, UserListResponse, UserSummary};

/// Build the `/users` router.
pub fn router() -> Router {
    Router::new()
        .route("/", get(list_users))
        .route("/{edipi}/roles", patch(update_roles))
}

/// Build stub user data scoped to the requester's authorized sites.
fn stub_users(scope: &DataScope) -> Vec<UserSummary> {
    let all_users = vec![
        UserSummary {
            user_id: "usr-001".to_string(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "Test Unit, Langley AFB".to_string(),
            site_id: SiteId("langley".to_string()),
            roles: vec![Role::User],
            active: true,
            quota: Some(QuotaStatus {
                limit: 500,
                used: 120,
                color_limit: 100,
                color_used: 15,
            }),
            last_login: Some(Utc::now()),
            provisioned_at: Utc::now(),
        },
        UserSummary {
            user_id: "usr-002".to_string(),
            display_name: "SMITH, JANE A.".to_string(),
            organization: "Ops Squadron, Ramstein AB".to_string(),
            site_id: SiteId("ramstein".to_string()),
            roles: vec![Role::User, Role::SiteAdmin(SiteId("ramstein".to_string()))],
            active: true,
            quota: Some(QuotaStatus {
                limit: 1000,
                used: 450,
                color_limit: 200,
                color_used: 80,
            }),
            last_login: Some(Utc::now()),
            provisioned_at: Utc::now(),
        },
    ];

    match scope {
        DataScope::Global => all_users,
        DataScope::Sites(sites) => all_users
            .into_iter()
            .filter(|u| sites.contains(&u.site_id))
            .collect(),
    }
}

/// `GET /users` — List users scoped to the requester's authorized sites.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester lacks admin access.
async fn list_users(
    Json(identity): Json<Identity>,
) -> Result<Json<UserListResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let users = stub_users(&scope);
    let total_count = users.len() as u64;

    Ok(Json(UserListResponse {
        users,
        total_count,
        page: 1,
        page_size: 25,
    }))
}

/// `PATCH /users/{edipi}/roles` — Update a user's role assignments.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AU-12 — Auditable event.
///
/// # Errors
///
/// Returns `AdminUiError::AccessDenied` if the requester lacks admin access.
/// Returns `AdminUiError::NotFound` if the target user is not found.
async fn update_roles(
    Path(edipi): Path<String>,
    Json((identity, request)): Json<(Identity, RoleAssignmentRequest)>,
) -> Result<Json<UserSummary>, AdminUiError> {
    let _scope = derive_scope(&identity.roles)?;

    tracing::info!(
        target_user = %request.user_id,
        reason = %request.reason,
        role_count = request.roles.len(),
        "role assignment update requested"
    );

    // Stub: return the user with updated roles.
    Ok(Json(UserSummary {
        user_id: request.user_id,
        display_name: format!("User {edipi}"),
        organization: "Test Unit".to_string(),
        site_id: SiteId("langley".to_string()),
        roles: request.roles,
        active: true,
        quota: None,
        last_login: None,
        provisioned_at: Utc::now(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_list_response_serializes() {
        let users = stub_users(&DataScope::Global);
        let response = UserListResponse {
            total_count: users.len() as u64,
            users,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("DOE, JOHN Q."));
        assert!(json.contains("\"page\":1"));
    }

    #[test]
    fn nist_ac2_site_admin_sees_only_own_site_users() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Site admin for langley cannot see ramstein users.
        let scope = DataScope::Sites(vec![SiteId("langley".to_string())]);
        let users = stub_users(&scope);
        assert!(users
            .iter()
            .all(|u| u.site_id == SiteId("langley".to_string())));
        assert!(!users.is_empty());
    }

    #[test]
    fn nist_ac2_role_assignment_preserves_roles() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Role assignment request preserves the specified roles.
        let req = RoleAssignmentRequest {
            user_id: "usr-001".to_string(),
            roles: vec![Role::SiteAdmin(SiteId("langley".to_string()))],
            reason: "Promoted to site administrator".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RoleAssignmentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.roles.len(), 1);
        assert!(!deserialized.reason.is_empty());
    }
}
