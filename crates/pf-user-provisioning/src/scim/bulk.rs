// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SCIM` 2.0 Bulk Operations (`RFC 7644` Section 3.7).
//!
//! Supports `POST /scim/v2/Bulk` with an array of operations for initial
//! provisioning of users from `Entra ID` or an LDAP-to-SCIM bridge.
//!
//! **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::repository::UserRepository;

use super::endpoints::ScimAuthConfig;
use super::schema::{
    ScimErrorResponse, ScimUser, provisioned_user_to_scim, scim_user_to_provisioned,
};

/// The `SCIM` Bulk Request schema URI.
pub const SCIM_BULK_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";

/// The `SCIM` Bulk Response schema URI.
pub const SCIM_BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

/// A `SCIM` 2.0 Bulk Request (`RFC 7644` Section 3.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRequest {
    /// The schema URIs (must include the Bulk Request schema).
    pub schemas: Vec<String>,

    /// The list of bulk operations to perform.
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperation>,

    /// Maximum number of errors before aborting (0 = unlimited).
    #[serde(default)]
    pub fail_on_errors: usize,
}

/// A single operation within a `SCIM` Bulk Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkOperation {
    /// The HTTP method: `"POST"`, `"PUT"`, `"PATCH"`, or `"DELETE"`.
    pub method: String,

    /// The resource path (e.g., `"/Users"` or `"/Users/{id}"`).
    pub path: String,

    /// A client-defined identifier for correlating responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,

    /// The resource data (for `POST` and `PUT`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ScimUser>,
}

/// A `SCIM` 2.0 Bulk Response (`RFC 7644` Section 3.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResponse {
    /// The schema URIs.
    pub schemas: Vec<String>,

    /// The list of operation results.
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResponse>,
}

/// The result of a single bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkOperationResponse {
    /// The HTTP method that was performed.
    pub method: String,

    /// The client-defined bulk identifier (echoed back).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,

    /// The resource location (for successful `POST`/`PUT`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// The HTTP status code for this operation.
    pub status: String,

    /// The created/updated resource (for successful `POST`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ScimUser>,

    /// An error response (for failed operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ScimErrorResponse>,
}

/// Handle `POST /scim/v2/Bulk` — Execute bulk operations.
///
/// **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management
///
/// Processes an array of `SCIM` operations (currently supports `POST` for
/// user creation). Operations are applied sequentially. If `fail_on_errors`
/// is set and the error count exceeds it, remaining operations are skipped.
///
/// # Errors
///
/// Returns a [`BulkResponse`] where each operation has its own status.
/// Returns `None` if the bearer token is invalid.
pub fn execute_bulk(
    bearer_token: &SecretString,
    request: &BulkRequest,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
    max_operations: usize,
) -> Result<BulkResponse, ScimErrorResponse> {
    // Validate bearer token.
    if bearer_token.expose_secret() != config.bearer_token.expose_secret() {
        warn!("SCIM bulk request rejected: invalid bearer token");
        return Err(ScimErrorResponse::new("unauthorized", 401));
    }

    // Enforce operation limit.
    if request.operations.len() > max_operations {
        return Err(ScimErrorResponse::new(
            &format!("too many operations (max: {max_operations})"),
            413,
        ));
    }

    let mut responses = Vec::with_capacity(request.operations.len());
    let mut error_count: usize = 0;

    for op in &request.operations {
        // Check fail_on_errors threshold.
        if request.fail_on_errors > 0 && error_count >= request.fail_on_errors {
            responses.push(BulkOperationResponse {
                method: op.method.clone(),
                bulk_id: op.bulk_id.clone(),
                location: None,
                status: "412".to_string(),
                response: None,
                error: Some(ScimErrorResponse::new(
                    "bulk operation aborted: error threshold exceeded",
                    412,
                )),
            });
            continue;
        }

        let result = execute_single_bulk_op(op, repo, config);
        if result.status.starts_with('4') || result.status.starts_with('5') {
            error_count += 1;
        }
        responses.push(result);
    }

    info!(
        total = request.operations.len(),
        errors = error_count,
        "SCIM bulk operation completed"
    );

    Ok(BulkResponse {
        schemas: vec![SCIM_BULK_RESPONSE_SCHEMA.to_string()],
        operations: responses,
    })
}

/// Execute a single bulk operation.
fn execute_single_bulk_op(
    op: &BulkOperation,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> BulkOperationResponse {
    match op.method.to_uppercase().as_str() {
        "POST" => execute_bulk_post(op, repo, config),
        "DELETE" => execute_bulk_delete(op, repo),
        other => BulkOperationResponse {
            method: other.to_string(),
            bulk_id: op.bulk_id.clone(),
            location: None,
            status: "400".to_string(),
            response: None,
            error: Some(ScimErrorResponse::new(
                &format!("unsupported bulk method: {other}"),
                400,
            )),
        },
    }
}

/// Execute a bulk `POST` (create user).
fn execute_bulk_post(
    op: &BulkOperation,
    repo: &dyn UserRepository,
    config: &ScimAuthConfig,
) -> BulkOperationResponse {
    let Some(scim_user) = &op.data else {
        return BulkOperationResponse {
            method: "POST".to_string(),
            bulk_id: op.bulk_id.clone(),
            location: None,
            status: "400".to_string(),
            response: None,
            error: Some(ScimErrorResponse::new("missing user data", 400)),
        };
    };

    let user = match scim_user_to_provisioned(scim_user) {
        Ok(u) => u,
        Err(e) => {
            warn!(error = %e, "SCIM bulk POST: invalid user data");
            return BulkOperationResponse {
                method: "POST".to_string(),
                bulk_id: op.bulk_id.clone(),
                location: None,
                status: "400".to_string(),
                response: None,
                error: Some(ScimErrorResponse::new("invalid user data", 400)),
            };
        }
    };

    if let Err(e) = repo.create(&user) {
        warn!(error = %e, "SCIM bulk POST: repository error");
        return BulkOperationResponse {
            method: "POST".to_string(),
            bulk_id: op.bulk_id.clone(),
            location: None,
            status: "409".to_string(),
            response: None,
            error: Some(ScimErrorResponse::new("user creation failed", 409)),
        };
    }

    let scim_result = provisioned_user_to_scim(&user, &config.base_url);
    let location = scim_result.meta.as_ref().and_then(|m| m.location.clone());

    BulkOperationResponse {
        method: "POST".to_string(),
        bulk_id: op.bulk_id.clone(),
        location,
        status: "201".to_string(),
        response: Some(scim_result),
        error: None,
    }
}

/// Execute a bulk `DELETE` (deactivate user).
fn execute_bulk_delete(op: &BulkOperation, repo: &dyn UserRepository) -> BulkOperationResponse {
    // Extract user ID from path: /Users/{id}
    let user_id = op.path.strip_prefix("/Users/").unwrap_or("");

    let Ok(uuid) = uuid::Uuid::parse_str(user_id) else {
        return BulkOperationResponse {
            method: "DELETE".to_string(),
            bulk_id: op.bulk_id.clone(),
            location: None,
            status: "400".to_string(),
            response: None,
            error: Some(ScimErrorResponse::new("invalid user ID in path", 400)),
        };
    };

    // Find user by iterating (same approach as endpoints).
    let active = repo
        .list_by_status(crate::user::UserStatus::Active)
        .unwrap_or_default();
    let suspended = repo
        .list_by_status(crate::user::UserStatus::Suspended)
        .unwrap_or_default();
    let all_users = active.into_iter().chain(suspended);

    let Some(user) = all_users.into_iter().find(|u| u.id == uuid) else {
        return BulkOperationResponse {
            method: "DELETE".to_string(),
            bulk_id: op.bulk_id.clone(),
            location: None,
            status: "404".to_string(),
            response: None,
            error: Some(ScimErrorResponse::new("user not found", 404)),
        };
    };

    if let Err(e) = repo.update_status(&user.edipi, crate::user::UserStatus::Suspended) {
        warn!(error = %e, "SCIM bulk DELETE: repository error");
        return BulkOperationResponse {
            method: "DELETE".to_string(),
            bulk_id: op.bulk_id.clone(),
            location: None,
            status: "500".to_string(),
            response: None,
            error: Some(ScimErrorResponse::new("deactivation failed", 500)),
        };
    }

    BulkOperationResponse {
        method: "DELETE".to_string(),
        bulk_id: op.bulk_id.clone(),
        location: None,
        status: "204".to_string(),
        response: None,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryUserRepository;
    use crate::user::{ProvisionedUser, ProvisioningSource, UserPreferences, UserStatus};
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

    fn test_scim_user(edipi: &str) -> ScimUser {
        ScimUser {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
            id: None,
            user_name: edipi.to_string(),
            name: None,
            display_name: Some("DOE, BULK B.".to_string()),
            active: true,
            emails: vec![],
            meta: None,
            enterprise_user: None,
        }
    }

    fn test_user(edipi_str: &str) -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new(edipi_str).unwrap(),
            display_name: "DOE, TEST T.".to_string(),
            organization: "Test Unit".to_string(),
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

    #[test]
    fn bulk_create_users_success() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![
                BulkOperation {
                    method: "POST".to_string(),
                    path: "/Users".to_string(),
                    bulk_id: Some("1".to_string()),
                    data: Some(test_scim_user("1234567890")),
                },
                BulkOperation {
                    method: "POST".to_string(),
                    path: "/Users".to_string(),
                    bulk_id: Some("2".to_string()),
                    data: Some(test_scim_user("0987654321")),
                },
            ],
            fail_on_errors: 0,
        };

        let response = execute_bulk(&valid_token(), &request, &repo, &config, 1000).unwrap();
        assert_eq!(response.operations.len(), 2);
        assert_eq!(response.operations[0].status, "201");
        assert_eq!(response.operations[1].status, "201");
    }

    #[test]
    fn bulk_invalid_token() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![],
            fail_on_errors: 0,
        };

        let result = execute_bulk(&invalid_token(), &request, &repo, &config, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn bulk_exceeds_max_operations() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![BulkOperation {
                method: "POST".to_string(),
                path: "/Users".to_string(),
                bulk_id: Some("1".to_string()),
                data: Some(test_scim_user("1234567890")),
            }],
            fail_on_errors: 0,
        };

        // Set max_operations to 0 to trigger the limit.
        let result = execute_bulk(&valid_token(), &request, &repo, &config, 0);
        assert!(result.is_err());
    }

    #[test]
    fn bulk_fail_on_errors_threshold() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        // First create a user so the second POST with same EDIPI fails.
        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![
                BulkOperation {
                    method: "POST".to_string(),
                    path: "/Users".to_string(),
                    bulk_id: Some("1".to_string()),
                    data: Some(test_scim_user("1234567890")),
                },
                BulkOperation {
                    method: "POST".to_string(),
                    path: "/Users".to_string(),
                    bulk_id: Some("2".to_string()),
                    data: Some(test_scim_user("1234567890")), // duplicate
                },
                BulkOperation {
                    method: "POST".to_string(),
                    path: "/Users".to_string(),
                    bulk_id: Some("3".to_string()),
                    data: Some(test_scim_user("1111111111")),
                },
            ],
            fail_on_errors: 1,
        };

        let response = execute_bulk(&valid_token(), &request, &repo, &config, 1000).unwrap();
        assert_eq!(response.operations.len(), 3);
        assert_eq!(response.operations[0].status, "201");
        assert_eq!(response.operations[1].status, "409"); // duplicate
        assert_eq!(response.operations[2].status, "412"); // aborted
    }

    #[test]
    fn bulk_delete_user() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();
        let user = test_user("1234567890");
        let user_id = user.id.to_string();
        repo.create(&user).unwrap();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![BulkOperation {
                method: "DELETE".to_string(),
                path: format!("/Users/{user_id}"),
                bulk_id: Some("1".to_string()),
                data: None,
            }],
            fail_on_errors: 0,
        };

        let response = execute_bulk(&valid_token(), &request, &repo, &config, 1000).unwrap();
        assert_eq!(response.operations[0].status, "204");

        // Verify user is suspended.
        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(found.status, UserStatus::Suspended);
    }

    #[test]
    fn bulk_unsupported_method() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![BulkOperation {
                method: "OPTIONS".to_string(),
                path: "/Users".to_string(),
                bulk_id: Some("1".to_string()),
                data: None,
            }],
            fail_on_errors: 0,
        };

        let response = execute_bulk(&valid_token(), &request, &repo, &config, 1000).unwrap();
        assert_eq!(response.operations[0].status, "400");
    }

    #[test]
    fn bulk_post_missing_data() {
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![BulkOperation {
                method: "POST".to_string(),
                path: "/Users".to_string(),
                bulk_id: Some("1".to_string()),
                data: None,
            }],
            fail_on_errors: 0,
        };

        let response = execute_bulk(&valid_token(), &request, &repo, &config, 1000).unwrap();
        assert_eq!(response.operations[0].status, "400");
    }

    #[test]
    fn nist_ac2_1_bulk_creates_users_via_automated_provisioning() {
        // NIST 800-53 Rev 5: AC-2(1) — Automated Account Management
        // Evidence: Bulk POST creates users with ProvisioningSource::Scim.
        let repo = InMemoryUserRepository::new();
        let config = test_config();

        let request = BulkRequest {
            schemas: vec![SCIM_BULK_REQUEST_SCHEMA.to_string()],
            operations: vec![BulkOperation {
                method: "POST".to_string(),
                path: "/Users".to_string(),
                bulk_id: Some("1".to_string()),
                data: Some(test_scim_user("1234567890")),
            }],
            fail_on_errors: 0,
        };

        let response = execute_bulk(&valid_token(), &request, &repo, &config, 1000).unwrap();
        assert_eq!(response.operations[0].status, "201");

        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(found.provisioning_source, ProvisioningSource::Scim);
    }

    #[test]
    fn bulk_response_serialization() {
        let response = BulkResponse {
            schemas: vec![SCIM_BULK_RESPONSE_SCHEMA.to_string()],
            operations: vec![BulkOperationResponse {
                method: "POST".to_string(),
                bulk_id: Some("1".to_string()),
                location: Some("https://printforge.local/scim/v2/Users/123".to_string()),
                status: "201".to_string(),
                response: None,
                error: None,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Operations"));
        assert!(json.contains("201"));
    }
}
