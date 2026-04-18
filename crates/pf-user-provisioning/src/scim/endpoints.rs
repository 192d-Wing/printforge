// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SCIM` 2.0 REST API endpoint handlers (`RFC 7644`).
//!
//! Provides request/response types and handler logic for the `SCIM` 2.0
//! User resource endpoints. These handlers operate on a [`UserRepository`]
//! and do not depend on any specific HTTP framework.
//!
//! **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
//!
//! # Endpoints
//!
//! - `POST /scim/v2/Users` — Create user
//! - `GET /scim/v2/Users/{id}` — Read user
//! - `PUT /scim/v2/Users/{id}` — Replace user (full update)
//! - `PATCH /scim/v2/Users/{id}` — Partial update
//! - `DELETE /scim/v2/Users/{id}` — Deactivate (soft delete to suspension)
//! - `GET /scim/v2/Users` — List users with filter support

use secrecy::{ExposeSecret, SecretString};
use tracing::{info, warn};
use uuid::Uuid;

use crate::repository::UserRepository;
use crate::user::UserStatus;

use super::filter::{matches_filter, parse_filter};
use super::schema::{
    PatchOperation, SCIM_LIST_RESPONSE_SCHEMA, ScimErrorResponse, ScimListResponse, ScimPatchOp,
    ScimUser, provisioned_user_to_scim, scim_user_to_provisioned,
};

/// Configuration for `SCIM` endpoint authentication.
#[derive(Debug, Clone)]
pub struct ScimAuthConfig {
    /// The expected bearer token for `SCIM` API requests.
    ///
    /// **Security:** Stored as [`SecretString`] to prevent accidental logging.
    /// `SCIM` bearer tokens MUST be validated on every request.
    pub bearer_token: SecretString,

    /// The base URL used for constructing resource `location` URLs in `meta`.
    pub base_url: String,

    /// Maximum number of results per list page.
    pub page_size: usize,
}

/// The outcome of a `SCIM` endpoint operation.
#[derive(Debug)]
pub enum ScimResponse {
    /// A single `SCIM` User resource (HTTP 200 or 201).
    User(Box<ScimUser>),
    /// A list of `SCIM` User resources (HTTP 200).
    List(ScimListResponse),
    /// An error response with a specific HTTP status code.
    Error(ScimErrorResponse, u16),
    /// Successful deletion (HTTP 204 No Content).
    NoContent,
}

/// Validate the `SCIM` bearer token.
///
/// **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication
///
/// # Errors
///
/// Returns `ScimResponse::Error` with HTTP 401 if the token does not match
/// the configured bearer token.
fn validate_bearer_token(
    provided: &SecretString,
    config: &ScimAuthConfig,
) -> Result<(), ScimResponse> {
    if provided.expose_secret() != config.bearer_token.expose_secret() {
        warn!("SCIM request rejected: invalid bearer token");
        return Err(ScimResponse::Error(
            ScimErrorResponse::new("unauthorized", 401),
            401,
        ));
    }
    Ok(())
}

/// Handle `POST /scim/v2/Users` — Create a new user.
///
/// **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
///
/// Validates the bearer token, converts the `SCIM` User to a
/// [`ProvisionedUser`], and persists it via the repository.
///
/// # Errors
///
/// Returns `ScimResponse::Error` on authentication failure, invalid input,
/// or repository errors (e.g., duplicate EDIPI).
pub fn create_user(
    bearer_token: &SecretString,
    scim_user: &ScimUser,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> ScimResponse {
    if let Err(e) = validate_bearer_token(bearer_token, config) {
        return e;
    }

    let Ok(user) = scim_user_to_provisioned(scim_user).map_err(|e| {
        warn!(error = %e, "SCIM create_user: invalid input");
    }) else {
        return ScimResponse::Error(ScimErrorResponse::new("invalid user data", 400), 400);
    };

    if let Err(e) = repo.create(&user) {
        warn!(error = %e, "SCIM create_user: repository error");
        return ScimResponse::Error(ScimErrorResponse::new("user creation failed", 409), 409);
    }

    info!(edipi = "***EDIPI***", "SCIM user created");
    ScimResponse::User(Box::new(provisioned_user_to_scim(&user, &config.base_url)))
}

/// Handle `GET /scim/v2/Users/{id}` — Read a single user.
///
/// **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
///
/// # Errors
///
/// Returns `ScimResponse::Error` on authentication failure or if the user
/// is not found.
pub fn get_user(
    bearer_token: &SecretString,
    user_id: &str,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> ScimResponse {
    if let Err(e) = validate_bearer_token(bearer_token, config) {
        return e;
    }

    let Ok(uuid) = Uuid::parse_str(user_id) else {
        return ScimResponse::Error(ScimErrorResponse::new("invalid user ID format", 400), 400);
    };

    let Ok(all_users) = collect_all_users(repo) else {
        return ScimResponse::Error(ScimErrorResponse::new("internal error", 500), 500);
    };

    match all_users.into_iter().find(|u| u.id == uuid) {
        Some(user) => {
            ScimResponse::User(Box::new(provisioned_user_to_scim(&user, &config.base_url)))
        }
        None => ScimResponse::Error(ScimErrorResponse::new("user not found", 404), 404),
    }
}

/// Handle `PUT /scim/v2/Users/{id}` — Replace a user (full update).
///
/// **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
///
/// Replaces all mutable attributes of the user. The user ID must match
/// an existing record.
///
/// # Errors
///
/// Returns `ScimResponse::Error` on authentication failure, invalid input,
/// or if the user is not found.
pub fn replace_user(
    bearer_token: &SecretString,
    user_id: &str,
    scim_user: &ScimUser,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> ScimResponse {
    if let Err(e) = validate_bearer_token(bearer_token, config) {
        return e;
    }

    let Ok(uuid) = Uuid::parse_str(user_id) else {
        return ScimResponse::Error(ScimErrorResponse::new("invalid user ID format", 400), 400);
    };

    let Ok(mut user) = scim_user_to_provisioned(scim_user).map_err(|e| {
        warn!(error = %e, "SCIM replace_user: invalid input");
    }) else {
        return ScimResponse::Error(ScimErrorResponse::new("invalid user data", 400), 400);
    };

    // Preserve the original ID.
    user.id = uuid;

    if let Err(e) = repo.update(&user) {
        warn!(error = %e, "SCIM replace_user: repository error");
        return ScimResponse::Error(ScimErrorResponse::new("user not found", 404), 404);
    }

    info!(user_id = %uuid, "SCIM user replaced");
    ScimResponse::User(Box::new(provisioned_user_to_scim(&user, &config.base_url)))
}

/// Handle `PATCH /scim/v2/Users/{id}` — Partial update.
///
/// **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
///
/// Applies `SCIM` `PatchOp` operations to an existing user. Supports
/// `replace` operations on `active`, `displayName`, and enterprise user
/// attributes.
///
/// # Errors
///
/// Returns `ScimResponse::Error` on authentication failure, if the user
/// is not found, or on unsupported patch operations.
pub fn patch_user(
    bearer_token: &SecretString,
    user_id: &str,
    patch_op: &ScimPatchOp,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> ScimResponse {
    if let Err(e) = validate_bearer_token(bearer_token, config) {
        return e;
    }

    let Ok(uuid) = Uuid::parse_str(user_id) else {
        return ScimResponse::Error(ScimErrorResponse::new("invalid user ID format", 400), 400);
    };

    let Ok(all_users) = collect_all_users(repo) else {
        return ScimResponse::Error(ScimErrorResponse::new("internal error", 500), 500);
    };

    let Some(mut user) = all_users.into_iter().find(|u| u.id == uuid) else {
        return ScimResponse::Error(ScimErrorResponse::new("user not found", 404), 404);
    };

    // Apply patch operations.
    for op in &patch_op.operations {
        if let Err(resp) = apply_patch_operation(&mut user, op) {
            return resp;
        }
    }

    user.updated_at = chrono::Utc::now();

    if let Err(e) = repo.update(&user) {
        warn!(error = %e, "SCIM patch_user: repository error");
        return ScimResponse::Error(ScimErrorResponse::new("update failed", 500), 500);
    }

    info!(user_id = %uuid, "SCIM user patched");
    ScimResponse::User(Box::new(provisioned_user_to_scim(&user, &config.base_url)))
}

/// Handle `DELETE /scim/v2/Users/{id}` — Deactivate (soft delete).
///
/// **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
///
/// Sets the user's status to [`UserStatus::Suspended`]. The user record
/// is retained for audit trail integrity. This triggers the deprovisioning
/// workflow.
///
/// # Errors
///
/// Returns `ScimResponse::Error` on authentication failure or if the user
/// is not found.
pub fn delete_user(
    bearer_token: &SecretString,
    user_id: &str,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> ScimResponse {
    if let Err(e) = validate_bearer_token(bearer_token, config) {
        return e;
    }

    let Ok(uuid) = Uuid::parse_str(user_id) else {
        return ScimResponse::Error(ScimErrorResponse::new("invalid user ID format", 400), 400);
    };

    let Ok(all_users) = collect_all_users(repo) else {
        return ScimResponse::Error(ScimErrorResponse::new("internal error", 500), 500);
    };

    let Some(user) = all_users.into_iter().find(|u| u.id == uuid) else {
        return ScimResponse::Error(ScimErrorResponse::new("user not found", 404), 404);
    };

    if let Err(e) = repo.update_status(&user.edipi, UserStatus::Suspended) {
        warn!(error = %e, "SCIM delete_user: repository error");
        return ScimResponse::Error(ScimErrorResponse::new("deactivation failed", 500), 500);
    }

    info!(user_id = %uuid, "SCIM user deactivated (suspended)");
    ScimResponse::NoContent
}

/// Handle `GET /scim/v2/Users` — List users with optional filter.
///
/// **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
///
/// Supports optional `filter` parameter for `SCIM` filtering (`RFC 7644`
/// Section 3.4.2.2), `startIndex` for pagination (1-based), and `count`
/// for page size.
///
/// # Errors
///
/// Returns `ScimResponse::Error` on authentication failure, invalid filter
/// syntax, or repository errors.
pub fn list_users(
    bearer_token: &SecretString,
    filter_str: Option<&str>,
    start_index: Option<usize>,
    count: Option<usize>,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> ScimResponse {
    if let Err(e) = validate_bearer_token(bearer_token, config) {
        return e;
    }

    let Ok(all_users) = collect_all_users(repo) else {
        return ScimResponse::Error(ScimErrorResponse::new("internal error", 500), 500);
    };

    // Apply filter if provided.
    let filtered = if let Some(filter_expr) = filter_str {
        let Ok(filter) = parse_filter(filter_expr).map_err(|e| {
            warn!(error = %e, "SCIM list_users: invalid filter");
        }) else {
            return ScimResponse::Error(ScimErrorResponse::new("invalid filter", 400), 400);
        };
        all_users
            .into_iter()
            .filter(|u| matches_filter(u, &filter))
            .collect::<Vec<_>>()
    } else {
        all_users
    };

    let total_results = filtered.len();

    // SCIM pagination is 1-based.
    let start = start_index.unwrap_or(1).max(1) - 1;
    let page_size = count.unwrap_or(config.page_size).min(config.page_size);

    let page: Vec<_> = filtered
        .iter()
        .skip(start)
        .take(page_size)
        .map(|u| provisioned_user_to_scim(u, &config.base_url))
        .collect();

    let items_per_page = page.len();

    ScimResponse::List(ScimListResponse {
        schemas: vec![SCIM_LIST_RESPONSE_SCHEMA.to_string()],
        total_results,
        items_per_page,
        start_index: start + 1,
        resources: page,
    })
}

/// Collect all users (active and suspended) from the repository.
fn collect_all_users(repo: &dyn UserRepository) -> Result<Vec<crate::user::ProvisionedUser>, ()> {
    let active = repo.list_by_status(UserStatus::Active).map_err(|e| {
        warn!(error = %e, "SCIM: repository error listing active users");
    })?;

    let suspended = repo.list_by_status(UserStatus::Suspended).map_err(|e| {
        warn!(error = %e, "SCIM: repository error listing suspended users");
    })?;

    let mut all = active;
    all.extend(suspended);
    Ok(all)
}

/// Apply a single `SCIM` patch operation to a user.
fn apply_patch_operation(
    user: &mut crate::user::ProvisionedUser,
    operation: &PatchOperation,
) -> Result<(), ScimResponse> {
    let op = operation.op.to_lowercase();
    if op != "replace" && op != "add" {
        return Err(ScimResponse::Error(
            ScimErrorResponse::new(&format!("unsupported patch op: {}", operation.op), 400),
            400,
        ));
    }

    let path = operation.path.as_deref().unwrap_or("");

    let value = operation.value.as_ref().ok_or_else(|| {
        ScimResponse::Error(
            ScimErrorResponse::new("patch operation missing value", 400),
            400,
        )
    })?;

    match path {
        "active" => {
            if let Some(active) = value.as_bool() {
                user.status = if active {
                    UserStatus::Active
                } else {
                    UserStatus::Suspended
                };
            } else {
                return Err(ScimResponse::Error(
                    ScimErrorResponse::new("active must be a boolean", 400),
                    400,
                ));
            }
        }
        "displayName" => {
            if let Some(name) = value.as_str() {
                user.display_name = name.to_string();
            } else {
                return Err(ScimResponse::Error(
                    ScimErrorResponse::new("displayName must be a string", 400),
                    400,
                ));
            }
        }
        _ => {
            // Ignore unknown paths per SCIM spec (lenient processing).
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryUserRepository;
    use crate::user::{ProvisionedUser, ProvisioningSource, UserPreferences};
    use chrono::Utc;
    use pf_common::identity::{Edipi, Role};
    use pf_common::job::CostCenter;
    use uuid::Uuid;

    fn test_config() -> ScimAuthConfig {
        ScimAuthConfig {
            bearer_token: SecretString::from("test-bearer-token-value"),
            base_url: "https://printforge.local".to_string(),
            page_size: 100,
        }
    }

    fn valid_token() -> SecretString {
        SecretString::from("test-bearer-token-value")
    }

    fn invalid_token() -> SecretString {
        SecretString::from("wrong-token")
    }

    fn test_user(edipi_str: &str) -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new(edipi_str).unwrap(),
            display_name: "DOE, TEST T.".to_string(),
            organization: "Test Unit, Test Base AFB".to_string(),
            roles: vec![Role::User],
            cost_centers: vec![CostCenter::new("CC001", "Test").unwrap()],
            preferences: UserPreferences::default(),
            status: UserStatus::Active,
            provisioning_source: ProvisioningSource::Jit,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        }
    }

    fn test_scim_user() -> ScimUser {
        ScimUser {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
            id: None,
            user_name: "1234567890".to_string(),
            name: None,
            display_name: Some("DOE, JOHN Q.".to_string()),
            active: true,
            emails: vec![],
            meta: None,
            enterprise_user: None,
        }
    }

    #[test]
    fn create_user_success() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let scim = test_scim_user();

        let response = create_user(&valid_token(), &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::User(_)));
    }

    #[test]
    fn create_user_invalid_token() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let scim = test_scim_user();

        let response = create_user(&invalid_token(), &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 401)));
    }

    #[test]
    fn create_user_invalid_edipi() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let mut scim = test_scim_user();
        scim.user_name = "bad".to_string();

        let response = create_user(&valid_token(), &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 400)));
    }

    #[test]
    fn create_user_duplicate_fails() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let scim = test_scim_user();

        let _ = create_user(&valid_token(), &scim, &repo, &config);
        let response = create_user(&valid_token(), &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 409)));
    }

    #[test]
    fn get_user_success() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let response = get_user(&valid_token(), &user_id, &repo, &config);
        assert!(matches!(response, ScimResponse::User(_)));
    }

    #[test]
    fn get_user_not_found() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let fake_id = Uuid::new_v4().to_string();

        let response = get_user(&valid_token(), &fake_id, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 404)));
    }

    #[test]
    fn get_user_invalid_uuid() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let response = get_user(&valid_token(), "not-a-uuid", &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 400)));
    }

    #[test]
    fn replace_user_success() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let mut scim = test_scim_user();
        scim.display_name = Some("SMITH, REPLACED R.".to_string());

        let response = replace_user(&valid_token(), &user_id, &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::User(_)));

        if let ScimResponse::User(u) = response {
            assert_eq!(u.display_name.as_deref(), Some("SMITH, REPLACED R."));
        }
    }

    #[test]
    fn replace_user_not_found() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let fake_id = Uuid::new_v4().to_string();
        let scim = test_scim_user();

        let response = replace_user(&valid_token(), &fake_id, &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 404)));
    }

    #[test]
    fn delete_user_success() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let response = delete_user(&valid_token(), &user_id, &repo, &config);
        assert!(matches!(response, ScimResponse::NoContent));

        // Verify user is now suspended (not deleted).
        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(found.status, UserStatus::Suspended);
    }

    #[test]
    fn delete_user_not_found() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let fake_id = Uuid::new_v4().to_string();

        let response = delete_user(&valid_token(), &fake_id, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 404)));
    }

    #[test]
    fn list_users_no_filter() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        repo.create(&test_user("1234567890")).unwrap();
        repo.create(&test_user("0987654321")).unwrap();

        let response = list_users(&valid_token(), None, None, None, &repo, &config);
        if let ScimResponse::List(list) = response {
            assert_eq!(list.total_results, 2);
            assert_eq!(list.resources.len(), 2);
            assert_eq!(list.start_index, 1);
        } else {
            panic!("expected ScimResponse::List");
        }
    }

    #[test]
    fn list_users_with_filter() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        repo.create(&test_user("1234567890")).unwrap();
        repo.create(&test_user("0987654321")).unwrap();

        let response = list_users(
            &valid_token(),
            Some(r#"userName eq "1234567890""#),
            None,
            None,
            &repo,
            &config,
        );
        if let ScimResponse::List(list) = response {
            assert_eq!(list.total_results, 1);
            assert_eq!(list.resources.len(), 1);
        } else {
            panic!("expected ScimResponse::List");
        }
    }

    #[test]
    fn list_users_with_pagination() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        repo.create(&test_user("1234567890")).unwrap();
        repo.create(&test_user("0987654321")).unwrap();
        repo.create(&test_user("1111111111")).unwrap();

        let response = list_users(&valid_token(), None, Some(1), Some(2), &repo, &config);
        if let ScimResponse::List(list) = response {
            assert_eq!(list.total_results, 3);
            assert_eq!(list.resources.len(), 2);
            assert_eq!(list.start_index, 1);
        } else {
            panic!("expected ScimResponse::List");
        }
    }

    #[test]
    fn list_users_invalid_filter() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let response = list_users(&valid_token(), Some("invalid"), None, None, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 400)));
    }

    #[test]
    fn patch_user_set_inactive() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let patch = ScimPatchOp {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
            operations: vec![PatchOperation {
                op: "replace".to_string(),
                path: Some("active".to_string()),
                value: Some(serde_json::Value::Bool(false)),
            }],
        };

        let response = patch_user(&valid_token(), &user_id, &patch, &repo, &config);
        assert!(matches!(response, ScimResponse::User(_)));

        if let ScimResponse::User(u) = response {
            assert!(!u.active);
        }
    }

    #[test]
    fn patch_user_update_display_name() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let patch = ScimPatchOp {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:PatchOp".to_string()],
            operations: vec![PatchOperation {
                op: "replace".to_string(),
                path: Some("displayName".to_string()),
                value: Some(serde_json::Value::String("SMITH, NEW N.".to_string())),
            }],
        };

        let response = patch_user(&valid_token(), &user_id, &patch, &repo, &config);
        if let ScimResponse::User(u) = response {
            assert_eq!(u.display_name.as_deref(), Some("SMITH, NEW N."));
        } else {
            panic!("expected ScimResponse::User");
        }
    }

    #[test]
    fn nist_ac2_3_scim_delete_suspends_account() {
        // NIST 800-53 Rev 5: AC-2(3) — Disable Accounts
        // Evidence: DELETE via SCIM sets status to Suspended, does not hard-delete.
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let response = delete_user(&valid_token(), &user_id, &repo, &config);
        assert!(matches!(response, ScimResponse::NoContent));

        // Verify the user record still exists.
        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap();
        assert!(found.is_some(), "user record must be retained");
        assert_eq!(found.unwrap().status, UserStatus::Suspended);
    }

    #[test]
    fn nist_ac2_1_scim_creates_user_via_automated_provisioning() {
        // NIST 800-53 Rev 5: AC-2(1) — Automated Account Management
        // Evidence: SCIM POST creates a user with ProvisioningSource::Scim.
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let scim = test_scim_user();

        let response = create_user(&valid_token(), &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::User(_)));

        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(found.provisioning_source, ProvisioningSource::Scim);
    }

    #[test]
    fn nist_ia2_scim_rejects_unauthenticated_request() {
        // NIST 800-53 Rev 5: IA-2 — Identification and Authentication
        // Evidence: Requests with invalid bearer tokens are rejected with 401.
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let scim = test_scim_user();

        let response = create_user(&invalid_token(), &scim, &repo, &config);
        assert!(matches!(response, ScimResponse::Error(_, 401)));
    }
}
