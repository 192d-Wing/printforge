// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! User management route handlers.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management

use axum::extract::{Path, State};
use axum::routing::{get, patch};
use axum::{Json, Router};

use pf_auth::middleware::RequireAuth;
use pf_common::identity::{Edipi, SiteId};
use pf_user_provisioning::{ProvisionedUser, UserFilter, UserStatus};

use crate::error::AdminUiError;
use crate::scope::{derive_scope, scope_to_installations};
use crate::state::AdminState;
use crate::user_mgmt::{RoleAssignmentRequest, UserListResponse, UserSummary};

/// Default page size when the client does not specify one.
const DEFAULT_PAGE_SIZE: usize = 25;

/// Build the `/users` router.
pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/", get(list_users))
        .route("/{edipi}/roles", patch(update_roles))
}

/// `GET /users` — List users scoped to the requester's authorized sites.
///
/// Backed by
/// [`UserService::list_users`](pf_user_provisioning::UserService::list_users)
/// with a `UserFilter.site_ids` filter derived from the caller's roles. The
/// quota field is reported as `None` for now — a batched quota lookup is
/// intentionally deferred to a later slice to avoid per-row round trips.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-3 — Access Enforcement
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` if the caller lacks an admin role.
/// - `AdminUiError::ServiceUnavailable` if the user service is not wired.
/// - `AdminUiError::Internal` on underlying user-service failure.
async fn list_users(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<UserListResponse>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let users_svc = state
        .users
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "users" })?;

    let filter = UserFilter {
        status: None,
        site_ids: scope_to_installations(&scope),
    };

    let (page, total_count) = users_svc
        .list_users(&filter, DEFAULT_PAGE_SIZE, 0)
        .map_err(|e| AdminUiError::Internal {
            source: Box::new(e),
        })?;

    let users = page.into_iter().map(to_user_summary).collect();

    Ok(Json(UserListResponse {
        users,
        total_count,
        page: 1,
        page_size: u32::try_from(DEFAULT_PAGE_SIZE).unwrap_or(25),
    }))
}

/// `PATCH /users/{edipi}/roles` — Update a user's role assignments.
///
/// Site Admins may only update users at their own sites; Fleet Admins may
/// update any user. The scope check happens after the user is fetched so we
/// know their `site_id` before comparing.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AU-12 — Auditable event.
///
/// # Errors
///
/// - `AdminUiError::AccessDenied` if the caller lacks an admin role.
/// - `AdminUiError::ScopeViolation` if the target user is outside the
///   caller's site scope.
/// - `AdminUiError::NotFound` if no user exists for `edipi`.
/// - `AdminUiError::ServiceUnavailable` if the user service is not wired.
/// - `AdminUiError::Internal` on underlying user-service failure.
async fn update_roles(
    State(state): State<AdminState>,
    RequireAuth(identity): RequireAuth,
    Path(edipi_str): Path<String>,
    Json(request): Json<RoleAssignmentRequest>,
) -> Result<Json<UserSummary>, AdminUiError> {
    let scope = derive_scope(&identity.roles)?;
    let users_svc = state
        .users
        .as_ref()
        .ok_or(AdminUiError::ServiceUnavailable { service: "users" })?;

    let edipi = Edipi::new(&edipi_str).map_err(AdminUiError::Validation)?;

    // Look up the target's site before applying the update so we can enforce
    // site scope. A site admin may not edit a user at another site.
    let existing = users_svc.get_user(&edipi).map_err(map_user_error)?;
    if !existing.site_id.is_empty() {
        crate::scope::require_site_access(&scope, &SiteId(existing.site_id.clone()))?;
    }

    tracing::info!(
        caller = %identity.edipi,
        target = %edipi,
        role_count = request.roles.len(),
        reason = %request.reason,
        "role assignment update"
    );

    let updated = users_svc
        .update_roles(&edipi, request.roles)
        .map_err(map_user_error)?;

    Ok(Json(to_user_summary(updated)))
}

/// Map a [`pf_user_provisioning::ProvisioningError`] onto the admin-ui error type.
fn map_user_error(err: pf_user_provisioning::ProvisioningError) -> AdminUiError {
    if matches!(err, pf_user_provisioning::ProvisioningError::UserNotFound { .. }) {
        AdminUiError::NotFound {
            entity: "user".to_string(),
        }
    } else {
        AdminUiError::Internal {
            source: Box::new(err),
        }
    }
}

/// Map a [`ProvisionedUser`] onto the admin-ui wire type.
///
/// Quota is left `None` for now — the admin-ui list endpoint pre-dates a
/// batched quota lookup; users who need current quota should hit the
/// per-user detail endpoint (or wait for the batched slice).
fn to_user_summary(user: ProvisionedUser) -> UserSummary {
    UserSummary {
        user_id: user.edipi.as_str().to_string(),
        display_name: user.display_name,
        organization: user.organization,
        site_id: SiteId(user.site_id),
        roles: user.roles,
        active: user.status == UserStatus::Active,
        quota: None,
        last_login: user.last_login_at,
        provisioned_at: user.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pf_common::identity::Role;
    use pf_user_provisioning::user::{ProvisioningSource, UserPreferences};
    use uuid::Uuid;

    fn sample_provisioned(edipi: &str, site: &str, active: bool) -> ProvisionedUser {
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new(edipi).unwrap(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "Test Unit".to_string(),
            site_id: site.to_string(),
            roles: vec![Role::User],
            cost_centers: vec![],
            preferences: UserPreferences::default(),
            status: if active {
                UserStatus::Active
            } else {
                UserStatus::Suspended
            },
            provisioning_source: ProvisioningSource::Jit,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: Some(Utc::now()),
        }
    }

    #[test]
    fn to_user_summary_wraps_site_id() {
        let mapped = to_user_summary(sample_provisioned("1111111111", "langley", true));
        assert_eq!(mapped.site_id, SiteId("langley".to_string()));
        assert_eq!(mapped.user_id, "1111111111");
        assert!(mapped.active);
        assert!(mapped.quota.is_none());
    }

    #[test]
    fn to_user_summary_suspended_user_reports_inactive() {
        let mapped = to_user_summary(sample_provisioned("1111111111", "langley", false));
        assert!(!mapped.active);
    }

    #[test]
    fn nist_ac2_role_assignment_preserves_roles() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: RoleAssignmentRequest roundtrips without loss so the
        // role_count audited on the server matches the roles applied.
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

    #[test]
    fn user_list_response_serializes() {
        let response = UserListResponse {
            users: vec![],
            total_count: 0,
            page: 1,
            page_size: 25,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"page\":1"));
        assert!(json.contains("\"total_count\":0"));
    }
}
