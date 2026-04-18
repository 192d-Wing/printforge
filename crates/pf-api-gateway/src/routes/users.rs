// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! User management routes: list, get, update roles, and suspend users.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management,
//! AC-3 — Access Enforcement (admin-only routes).

use axum::extract::{Path, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::identity::{Edipi, Role};
use crate::error::ApiError;
use crate::middleware::auth::{RequireAuth, is_admin};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// A user summary for list responses.
#[derive(Debug, Serialize)]
pub struct UserSummary {
    /// The user's EDIPI (redacted in logs, shown in API for admin use).
    pub edipi: String,
    /// Display name.
    pub name: String,
    /// Organization.
    pub org: String,
    /// Assigned roles.
    pub roles: Vec<Role>,
    /// Whether the account is currently suspended.
    pub suspended: bool,
}

/// Response for listing users.
#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    /// Matching users.
    pub users: Vec<UserSummary>,
    /// Total count for pagination.
    pub total: u64,
}

/// Detailed user information.
#[derive(Debug, Serialize)]
pub struct UserDetailResponse {
    /// The user's EDIPI.
    pub edipi: String,
    /// Display name.
    pub name: String,
    /// Organization.
    pub org: String,
    /// Assigned roles.
    pub roles: Vec<Role>,
    /// Whether the account is currently suspended.
    pub suspended: bool,
    /// Total pages printed (lifetime).
    pub total_pages: u64,
    /// Total jobs submitted (lifetime).
    pub total_jobs: u64,
}

/// Request payload for updating user roles.
#[derive(Debug, Deserialize)]
pub struct UpdateRolesRequest {
    /// The new set of roles to assign to the user.
    pub roles: Vec<Role>,
}

/// Response after updating user roles.
#[derive(Debug, Serialize)]
pub struct UpdateRolesResponse {
    /// The user's EDIPI.
    pub edipi: String,
    /// Updated roles.
    pub roles: Vec<Role>,
}

/// Response after suspending a user.
#[derive(Debug, Serialize)]
pub struct SuspendUserResponse {
    /// The user's EDIPI.
    pub edipi: String,
    /// Whether the account is now suspended.
    pub suspended: bool,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the `/users` router.
///
/// - `GET /` and `PATCH /:edipi/roles` and `POST /:edipi/suspend` are admin-only.
/// - `GET /:edipi` allows the user to view their own profile or admin to view any.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users))
        .route("/{edipi}", get(get_user))
        .route("/{edipi}/roles", patch(update_roles))
        .route("/{edipi}/suspend", post(suspend_user))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all users (admin only).
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-3 — Access Enforcement.
///
/// # Errors
///
/// Returns `ApiError::forbidden` if the caller is not an admin.
async fn list_users(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
) -> Result<Json<ListUsersResponse>, ApiError> {
    if !is_admin(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let svc = state.user_service.as_ref().ok_or_else(|| {
        ApiError::service_unavailable(Uuid::now_v7())
    })?;

    let filter = pf_user_provisioning::UserFilter::default();
    let (users, total) = svc.list_users(&filter, 100, 0).map_err(|e| {
        tracing::error!(error = %e, "list_users service call failed");
        ApiError::internal(Uuid::now_v7(), e)
    })?;

    let summaries = users
        .into_iter()
        .map(|u| UserSummary {
            edipi: u.edipi.as_str().to_string(),
            name: u.display_name,
            org: u.organization,
            roles: u.roles,
            suspended: u.status == pf_user_provisioning::UserStatus::Suspended,
        })
        .collect();

    Ok(Json(ListUsersResponse {
        users: summaries,
        total,
    }))
}

/// Get user details.
///
/// Users can view their own profile. Admins can view any user.
///
/// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement.
///
/// # Errors
///
/// Returns `ApiError::forbidden` if a non-admin tries to view another user.
async fn get_user(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(edipi): Path<String>,
) -> Result<Json<UserDetailResponse>, ApiError> {
    let target_edipi = Edipi::new(&edipi)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid EDIPI format"))?;

    // AC-3: non-admins can only view their own profile.
    if identity.edipi.as_str() != target_edipi.as_str() && !is_admin(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let svc = state.user_service.as_ref().ok_or_else(|| {
        ApiError::service_unavailable(Uuid::now_v7())
    })?;

    let user = svc.get_user(&target_edipi).map_err(|e| {
        match e {
            pf_user_provisioning::ProvisioningError::UserNotFound { .. } => {
                ApiError::not_found(Uuid::now_v7())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(UserDetailResponse {
        edipi: user.edipi.as_str().to_string(),
        name: user.display_name,
        org: user.organization,
        roles: user.roles,
        suspended: user.status == pf_user_provisioning::UserStatus::Suspended,
        total_pages: 0,
        total_jobs: 0,
    }))
}

/// Update a user's roles (admin only).
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-3 — Access Enforcement.
///
/// # Errors
///
/// Returns `ApiError::forbidden` if the caller is not an admin.
async fn update_roles(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(edipi): Path<String>,
    Json(req): Json<UpdateRolesRequest>,
) -> Result<Json<UpdateRolesResponse>, ApiError> {
    if !is_admin(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let target_edipi = Edipi::new(&edipi)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid EDIPI format"))?;

    let svc = state.user_service.as_ref().ok_or_else(|| {
        ApiError::service_unavailable(Uuid::now_v7())
    })?;

    let updated = svc.update_roles(&target_edipi, req.roles).map_err(|e| {
        match e {
            pf_user_provisioning::ProvisioningError::UserNotFound { .. } => {
                ApiError::not_found(Uuid::now_v7())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(UpdateRolesResponse {
        edipi: updated.edipi.as_str().to_string(),
        roles: updated.roles,
    }))
}

/// Suspend a user account (admin only).
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AC-3 — Access Enforcement.
///
/// # Errors
///
/// Returns `ApiError::forbidden` if the caller is not an admin.
async fn suspend_user(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(edipi): Path<String>,
) -> Result<Json<SuspendUserResponse>, ApiError> {
    if !is_admin(&identity) {
        return Err(ApiError::forbidden(Uuid::now_v7()));
    }

    let target_edipi = Edipi::new(&edipi)
        .map_err(|_| ApiError::bad_request(Uuid::now_v7(), "invalid EDIPI format"))?;

    let svc = state.user_service.as_ref().ok_or_else(|| {
        ApiError::service_unavailable(Uuid::now_v7())
    })?;

    svc.suspend_user(&target_edipi).map_err(|e| {
        match e {
            pf_user_provisioning::ProvisioningError::UserNotFound { .. } => {
                ApiError::not_found(Uuid::now_v7())
            }
            other => ApiError::internal(Uuid::now_v7(), other),
        }
    })?;

    Ok(Json(SuspendUserResponse {
        edipi: target_edipi.as_str().to_string(),
        suspended: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_roles_request_deserializes() {
        let json = r#"{"roles": ["User"]}"#;
        let req: UpdateRolesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.roles.len(), 1);
    }

    #[test]
    fn user_summary_serializes() {
        let summary = UserSummary {
            edipi: "1234567890".to_string(),
            name: "DOE.JOHN.Q.1234567890".to_string(),
            org: "Test Unit".to_string(),
            roles: vec![Role::User],
            suspended: false,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("1234567890"));
    }
}
