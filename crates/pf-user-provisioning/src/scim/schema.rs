// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SCIM` 2.0 Core Schema types (`RFC 7643`).
//!
//! Defines the `SCIM` User resource representation, Enterprise User extension,
//! and conversions to/from the internal [`ProvisionedUser`] type.
//!
//! **NIST 800-53 Rev 5:** AC-2(1) — Automated Account Management

use chrono::{DateTime, Utc};
use pf_common::identity::{Edipi, Role};
use pf_common::job::CostCenter;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ProvisioningError;
use crate::user::{ProvisionedUser, ProvisioningSource, UserPreferences, UserStatus};

/// The `SCIM` 2.0 User resource schema URI.
pub const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// The `SCIM` Enterprise User extension schema URI.
pub const SCIM_ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// The `SCIM` List Response schema URI.
pub const SCIM_LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// The `SCIM` Error schema URI.
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// A `SCIM` 2.0 User resource (`RFC 7643` Section 4.1).
///
/// Maps to/from [`ProvisionedUser`] for internal storage. The `userName`
/// field is the user's EDIPI per `PrintForge` convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// The `SCIM` schema URIs this resource conforms to.
    pub schemas: Vec<String>,

    /// The unique internal identifier (UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// An identifier for the user, typically the EDIPI.
    pub user_name: String,

    /// The user's name components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,

    /// Display name (e.g., `"DOE, JOHN Q."`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Whether the user account is active.
    #[serde(default = "default_active")]
    pub active: bool,

    /// Email addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,

    /// Resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,

    /// Enterprise User extension attributes.
    #[serde(
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        skip_serializing_if = "Option::is_none"
    )]
    pub enterprise_user: Option<EnterpriseUserExtension>,
}

/// The `SCIM` Name sub-attribute (`RFC 7643` Section 4.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    /// The full name, suitable for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// The family (last) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// The given (first) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// The middle name(s) or initial(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
}

/// A `SCIM` email sub-attribute (`RFC 7643` Section 4.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    /// The email address value.
    pub value: String,

    /// The type of email (e.g., `"work"`, `"home"`).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,

    /// Whether this is the primary email.
    #[serde(default)]
    pub primary: bool,
}

/// `SCIM` resource metadata (`RFC 7643` Section 3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    /// The resource type (always `"User"` for user resources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,

    /// The `DateTime` the resource was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// The `DateTime` the resource was last modified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<DateTime<Utc>>,

    /// The URI of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// `SCIM` Enterprise User extension (`RFC 7643` Section 4.3).
///
/// Carries `PrintForge`-relevant attributes like organization and cost center.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseUserExtension {
    /// The organizational unit or command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// The cost center code for chargeback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_center: Option<String>,

    /// The department name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// A `SCIM` 2.0 List Response (`RFC 7644` Section 3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse {
    /// The schema URIs.
    pub schemas: Vec<String>,

    /// Total number of results matching the query.
    pub total_results: usize,

    /// The number of resources returned in this page.
    pub items_per_page: usize,

    /// The 1-based index of the first result in this page.
    pub start_index: usize,

    /// The list of `SCIM` User resources.
    #[serde(rename = "Resources")]
    pub resources: Vec<ScimUser>,
}

/// A `SCIM` 2.0 Error Response (`RFC 7644` Section 3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorResponse {
    /// The schema URIs (always the `SCIM` Error schema).
    pub schemas: Vec<String>,

    /// A human-readable error description.
    pub detail: String,

    /// The HTTP status code.
    pub status: String,
}

impl ScimErrorResponse {
    /// Create a new `SCIM` error response.
    #[must_use]
    pub fn new(detail: &str, status: u16) -> Self {
        Self {
            schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
            detail: detail.to_string(),
            status: status.to_string(),
        }
    }
}

/// A `SCIM` 2.0 Patch Operation (`RFC 7644` Section 3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOp {
    /// The schema URIs (always the `SCIM` `PatchOp` schema).
    pub schemas: Vec<String>,

    /// The list of patch operations to apply.
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

/// A single `SCIM` patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    /// The operation to perform: `"add"`, `"replace"`, or `"remove"`.
    pub op: String,

    /// The attribute path to modify (e.g., `"active"`, `"displayName"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// The new value for the attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

fn default_active() -> bool {
    true
}

/// Convert a [`ProvisionedUser`] to a [`ScimUser`] for API responses.
///
/// Maps internal fields to `SCIM` 2.0 schema representation. The `userName`
/// is the user's EDIPI, and account status maps to the `active` flag.
#[must_use]
pub fn provisioned_user_to_scim(user: &ProvisionedUser, base_url: &str) -> ScimUser {
    let cost_center_code = user.cost_centers.first().map(|cc| cc.code.clone());

    ScimUser {
        schemas: vec![
            SCIM_USER_SCHEMA.to_string(),
            SCIM_ENTERPRISE_USER_SCHEMA.to_string(),
        ],
        id: Some(user.id.to_string()),
        user_name: user.edipi.as_str().to_string(),
        name: Some(ScimName {
            formatted: Some(user.display_name.clone()),
            family_name: None,
            given_name: None,
            middle_name: None,
        }),
        display_name: Some(user.display_name.clone()),
        active: user.status == UserStatus::Active,
        emails: Vec::new(),
        meta: Some(ScimMeta {
            resource_type: Some("User".to_string()),
            created: Some(user.created_at),
            last_modified: Some(user.updated_at),
            location: Some(format!("{base_url}/scim/v2/Users/{}", user.id)),
        }),
        enterprise_user: Some(EnterpriseUserExtension {
            organization: Some(user.organization.clone()),
            cost_center: cost_center_code,
            department: None,
        }),
    }
}

/// Convert a [`ScimUser`] to a [`ProvisionedUser`] for internal storage.
///
/// # Errors
///
/// Returns `ProvisioningError::InvalidEdipi` if the `userName` is not a valid
/// EDIPI. Returns `ProvisioningError::MissingClaims` if required fields are
/// absent.
pub fn scim_user_to_provisioned(
    scim_user: &ScimUser,
) -> Result<ProvisionedUser, ProvisioningError> {
    let edipi = Edipi::new(&scim_user.user_name).map_err(ProvisioningError::InvalidEdipi)?;

    let display_name = scim_user
        .display_name
        .clone()
        .or_else(|| scim_user.name.as_ref().and_then(|n| n.formatted.clone()))
        .unwrap_or_else(|| scim_user.user_name.clone());

    let organization = scim_user
        .enterprise_user
        .as_ref()
        .and_then(|eu| eu.organization.clone())
        .unwrap_or_default();

    let cost_centers = scim_user
        .enterprise_user
        .as_ref()
        .and_then(|eu| eu.cost_center.as_ref())
        .and_then(|code| CostCenter::new(code, code).ok())
        .into_iter()
        .collect();

    let status = if scim_user.active {
        UserStatus::Active
    } else {
        UserStatus::Suspended
    };

    let now = Utc::now();

    Ok(ProvisionedUser {
        id: scim_user
            .id
            .as_ref()
            .and_then(|id| Uuid::parse_str(id).ok())
            .unwrap_or_else(Uuid::new_v4),
        edipi,
        display_name,
        organization,
        // SCIM schema has no standard site attribute — users provisioned
        // via SCIM start unattributed and get their site_id on their first
        // interactive login (JIT attribute sync from the OIDC `site` claim).
        site_id: String::new(),
        roles: vec![Role::User],
        cost_centers,
        preferences: UserPreferences::default(),
        status,
        provisioning_source: ProvisioningSource::Scim,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scim_user() -> ScimUser {
        ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.to_string()],
            id: None,
            user_name: "1234567890".to_string(),
            name: Some(ScimName {
                formatted: Some("DOE, JOHN Q.".to_string()),
                family_name: Some("Doe".to_string()),
                given_name: Some("John".to_string()),
                middle_name: Some("Q".to_string()),
            }),
            display_name: Some("DOE, JOHN Q.".to_string()),
            active: true,
            emails: vec![],
            meta: None,
            enterprise_user: Some(EnterpriseUserExtension {
                organization: Some("Test Unit, Test Base AFB".to_string()),
                cost_center: Some("CC001".to_string()),
                department: None,
            }),
        }
    }

    fn test_provisioned_user() -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new("1234567890").unwrap(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "Test Unit, Test Base AFB".to_string(),
            site_id: String::new(),
            roles: vec![Role::User],
            cost_centers: vec![CostCenter::new("CC001", "Test Cost Center").unwrap()],
            preferences: UserPreferences::default(),
            status: UserStatus::Active,
            provisioning_source: ProvisioningSource::Scim,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        }
    }

    #[test]
    fn scim_user_to_provisioned_valid() {
        let scim = test_scim_user();
        let user = scim_user_to_provisioned(&scim).unwrap();
        assert_eq!(user.edipi.as_str(), "1234567890");
        assert_eq!(user.display_name, "DOE, JOHN Q.");
        assert_eq!(user.organization, "Test Unit, Test Base AFB");
        assert!(user.is_active());
    }

    #[test]
    fn scim_user_to_provisioned_invalid_edipi() {
        let mut scim = test_scim_user();
        scim.user_name = "bad".to_string();
        let result = scim_user_to_provisioned(&scim);
        assert!(result.is_err());
    }

    #[test]
    fn scim_user_to_provisioned_inactive_maps_to_suspended() {
        let mut scim = test_scim_user();
        scim.active = false;
        let user = scim_user_to_provisioned(&scim).unwrap();
        assert_eq!(user.status, UserStatus::Suspended);
    }

    #[test]
    fn provisioned_user_to_scim_roundtrip() {
        let user = test_provisioned_user();
        let scim = provisioned_user_to_scim(&user, "https://printforge.local");
        assert_eq!(scim.user_name, "1234567890");
        assert_eq!(scim.display_name.as_deref(), Some("DOE, JOHN Q."));
        assert!(scim.active);
        assert!(scim.id.is_some());
        assert!(scim.meta.is_some());

        let meta = scim.meta.unwrap();
        assert_eq!(meta.resource_type.as_deref(), Some("User"));
    }

    #[test]
    fn scim_error_response_format() {
        let err = ScimErrorResponse::new("Not Found", 404);
        assert_eq!(err.status, "404");
        assert_eq!(err.detail, "Not Found");
        assert_eq!(err.schemas[0], SCIM_ERROR_SCHEMA);
    }

    #[test]
    fn scim_user_serialization_roundtrip() {
        let scim = test_scim_user();
        let json = serde_json::to_string(&scim).unwrap();
        let deserialized: ScimUser = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.user_name, scim.user_name);
        assert_eq!(deserialized.active, scim.active);
    }

    #[test]
    fn scim_list_response_serialization() {
        let response = ScimListResponse {
            schemas: vec![SCIM_LIST_RESPONSE_SCHEMA.to_string()],
            total_results: 1,
            items_per_page: 100,
            start_index: 1,
            resources: vec![test_scim_user()],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("totalResults"));
        assert!(json.contains("Resources"));
    }

    #[test]
    fn nist_ac2_1_scim_user_maps_provisioning_source_to_scim() {
        // NIST 800-53 Rev 5: AC-2(1) — Automated Account Management
        // Evidence: Users created from SCIM have ProvisioningSource::Scim
        let scim = test_scim_user();
        let user = scim_user_to_provisioned(&scim).unwrap();
        assert_eq!(user.provisioning_source, ProvisioningSource::Scim);
    }

    #[test]
    fn enterprise_user_extension_serialization() {
        let ext = EnterpriseUserExtension {
            organization: Some("Test Unit".to_string()),
            cost_center: Some("CC001".to_string()),
            department: Some("IT".to_string()),
        };
        let json = serde_json::to_string(&ext).unwrap();
        assert!(json.contains("organization"));
        assert!(json.contains("costCenter"));
    }
}
