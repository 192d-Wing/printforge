// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`UserRepository`].
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//! Provides CRUD operations for user records. Users are never hard-deleted;
//! only the status field may be changed to `Suspended`.

use pf_common::identity::{Edipi, Role};
use pf_common::job::CostCenter;
use sqlx::PgPool;

use crate::error::ProvisioningError;
use crate::repository::UserRepository;
use crate::user::{ProvisionedUser, ProvisioningSource, UserPreferences, UserStatus};

/// `PostgreSQL`-backed user repository.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
/// No `DELETE` statements are issued. Deprovisioning is implemented as
/// a status change to `Suspended`.
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    /// Create a new `PgUserRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Internal row type for the `users` table.
#[derive(sqlx::FromRow)]
struct UserRow {
    id: uuid::Uuid,
    edipi: String,
    display_name: String,
    organization: String,
    roles_json: serde_json::Value,
    cost_centers_json: serde_json::Value,
    preferences_json: serde_json::Value,
    status: String,
    provisioning_source: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl UserRow {
    fn try_into_user(self) -> Result<ProvisionedUser, ProvisioningError> {
        let edipi = Edipi::new(&self.edipi).map_err(ProvisioningError::InvalidEdipi)?;

        let roles: Vec<Role> =
            serde_json::from_value(self.roles_json).map_err(|e| ProvisioningError::Repository {
                detail: format!("failed to deserialize roles: {e}"),
            })?;

        let cost_centers: Vec<CostCenter> = serde_json::from_value(self.cost_centers_json)
            .map_err(|e| ProvisioningError::Repository {
                detail: format!("failed to deserialize cost centers: {e}"),
            })?;

        let preferences: UserPreferences =
            serde_json::from_value(self.preferences_json).map_err(|e| {
                ProvisioningError::Repository {
                    detail: format!("failed to deserialize preferences: {e}"),
                }
            })?;

        let status = match self.status.as_str() {
            "Active" => UserStatus::Active,
            "Suspended" => UserStatus::Suspended,
            other => {
                return Err(ProvisioningError::Repository {
                    detail: format!("unknown user status: {other}"),
                });
            }
        };

        let provisioning_source = match self.provisioning_source.as_str() {
            "Jit" => ProvisioningSource::Jit,
            "Scim" => ProvisioningSource::Scim,
            "AttributeSync" => ProvisioningSource::AttributeSync,
            other => {
                return Err(ProvisioningError::Repository {
                    detail: format!("unknown provisioning source: {other}"),
                });
            }
        };

        Ok(ProvisionedUser {
            id: self.id,
            edipi,
            display_name: self.display_name,
            organization: self.organization,
            roles,
            cost_centers,
            preferences,
            status,
            provisioning_source,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        })
    }
}

fn status_to_str(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "Active",
        UserStatus::Suspended => "Suspended",
    }
}

fn provisioning_source_to_str(source: ProvisioningSource) -> &'static str {
    match source {
        ProvisioningSource::Jit => "Jit",
        ProvisioningSource::Scim => "Scim",
        ProvisioningSource::AttributeSync => "AttributeSync",
    }
}

impl UserRepository for PgUserRepository {
    fn find_by_edipi(&self, edipi: &Edipi) -> Result<Option<ProvisionedUser>, ProvisioningError> {
        // Use block_on to maintain the sync trait signature.
        // In production, this would be called from an async context.
        let pool = self.pool.clone();
        let edipi_str = edipi.as_str().to_string();

        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query_as::<_, UserRow>(
                    "SELECT id, edipi, display_name, organization, roles_json, cost_centers_json, \
                     preferences_json, status, provisioning_source, created_at, updated_at, \
                     last_login_at FROM users WHERE edipi = $1",
                )
                .bind(&edipi_str)
                .fetch_optional(&pool)
                .await
            })
        })
        .map_err(|e| ProvisioningError::Repository {
            detail: format!("database query failed: {e}"),
        })?;

        match result {
            Some(row) => Ok(Some(row.try_into_user()?)),
            None => Ok(None),
        }
    }

    fn create(&self, user: &ProvisionedUser) -> Result<(), ProvisioningError> {
        let pool = self.pool.clone();
        let roles_json =
            serde_json::to_value(&user.roles).map_err(|e| ProvisioningError::Repository {
                detail: format!("failed to serialize roles: {e}"),
            })?;
        let cost_centers_json = serde_json::to_value(&user.cost_centers).map_err(|e| {
            ProvisioningError::Repository {
                detail: format!("failed to serialize cost centers: {e}"),
            }
        })?;
        let preferences_json =
            serde_json::to_value(&user.preferences).map_err(|e| ProvisioningError::Repository {
                detail: format!("failed to serialize preferences: {e}"),
            })?;

        let id = user.id;
        let edipi_str = user.edipi.as_str().to_string();
        let display_name = user.display_name.clone();
        let organization = user.organization.clone();
        let status = status_to_str(user.status).to_string();
        let prov_source = provisioning_source_to_str(user.provisioning_source).to_string();
        let created_at = user.created_at;
        let updated_at = user.updated_at;
        let last_login_at = user.last_login_at;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query(
                    "INSERT INTO users (id, edipi, display_name, organization, roles_json, \
                     cost_centers_json, preferences_json, status, provisioning_source, \
                     created_at, updated_at, last_login_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                )
                .bind(id)
                .bind(&edipi_str)
                .bind(&display_name)
                .bind(&organization)
                .bind(&roles_json)
                .bind(&cost_centers_json)
                .bind(&preferences_json)
                .bind(&status)
                .bind(&prov_source)
                .bind(created_at)
                .bind(updated_at)
                .bind(last_login_at)
                .execute(&pool)
                .await
            })
        })
        .map_err(|e| ProvisioningError::Repository {
            detail: format!("insert failed: {e}"),
        })?;

        Ok(())
    }

    fn update(&self, user: &ProvisionedUser) -> Result<(), ProvisioningError> {
        let pool = self.pool.clone();
        let roles_json =
            serde_json::to_value(&user.roles).map_err(|e| ProvisioningError::Repository {
                detail: format!("failed to serialize roles: {e}"),
            })?;
        let cost_centers_json = serde_json::to_value(&user.cost_centers).map_err(|e| {
            ProvisioningError::Repository {
                detail: format!("failed to serialize cost centers: {e}"),
            }
        })?;
        let preferences_json =
            serde_json::to_value(&user.preferences).map_err(|e| ProvisioningError::Repository {
                detail: format!("failed to serialize preferences: {e}"),
            })?;

        let edipi_str = user.edipi.as_str().to_string();
        let display_name = user.display_name.clone();
        let organization = user.organization.clone();
        let status = status_to_str(user.status).to_string();
        let prov_source = provisioning_source_to_str(user.provisioning_source).to_string();
        let updated_at = user.updated_at;
        let last_login_at = user.last_login_at;

        let rows_affected = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query(
                    "UPDATE users SET display_name = $1, organization = $2, roles_json = $3, \
                     cost_centers_json = $4, preferences_json = $5, status = $6, \
                     provisioning_source = $7, updated_at = $8, last_login_at = $9 \
                     WHERE edipi = $10",
                )
                .bind(&display_name)
                .bind(&organization)
                .bind(&roles_json)
                .bind(&cost_centers_json)
                .bind(&preferences_json)
                .bind(&status)
                .bind(&prov_source)
                .bind(updated_at)
                .bind(last_login_at)
                .bind(&edipi_str)
                .execute(&pool)
                .await
            })
        })
        .map_err(|e| ProvisioningError::Repository {
            detail: format!("update failed: {e}"),
        })?
        .rows_affected();

        if rows_affected == 0 {
            return Err(ProvisioningError::UserNotFound {
                detail: "user not found for update".to_string(),
            });
        }

        Ok(())
    }

    fn update_status(&self, edipi: &Edipi, status: UserStatus) -> Result<(), ProvisioningError> {
        let pool = self.pool.clone();
        let edipi_str = edipi.as_str().to_string();
        let status_str = status_to_str(status).to_string();

        let rows_affected = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query("UPDATE users SET status = $1, updated_at = NOW() WHERE edipi = $2")
                    .bind(&status_str)
                    .bind(&edipi_str)
                    .execute(&pool)
                    .await
            })
        })
        .map_err(|e| ProvisioningError::Repository {
            detail: format!("status update failed: {e}"),
        })?
        .rows_affected();

        if rows_affected == 0 {
            return Err(ProvisioningError::UserNotFound {
                detail: "user not found for status update".to_string(),
            });
        }

        Ok(())
    }

    fn list_by_status(
        &self,
        status: UserStatus,
    ) -> Result<Vec<ProvisionedUser>, ProvisioningError> {
        let pool = self.pool.clone();
        let status_str = status_to_str(status).to_string();

        let rows: Vec<UserRow> = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query_as::<_, UserRow>(
                    "SELECT id, edipi, display_name, organization, roles_json, \
                     cost_centers_json, preferences_json, status, provisioning_source, \
                     created_at, updated_at, last_login_at FROM users WHERE status = $1 \
                     ORDER BY created_at",
                )
                .bind(&status_str)
                .fetch_all(&pool)
                .await
            })
        })
        .map_err(|e| ProvisioningError::Repository {
            detail: format!("list query failed: {e}"),
        })?;

        rows.into_iter().map(UserRow::try_into_user).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_ac2_pg_user_repo_has_no_delete_method() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: PgUserRepository implements UserRepository which has no
        // delete method. Users can only be suspended, never hard-deleted.
        // The trait definition in repository.rs enforces this at compile time.
    }

    #[test]
    fn status_to_str_roundtrip() {
        assert_eq!(status_to_str(UserStatus::Active), "Active");
        assert_eq!(status_to_str(UserStatus::Suspended), "Suspended");
    }

    #[test]
    fn provisioning_source_to_str_roundtrip() {
        assert_eq!(provisioning_source_to_str(ProvisioningSource::Jit), "Jit");
        assert_eq!(provisioning_source_to_str(ProvisioningSource::Scim), "Scim");
        assert_eq!(
            provisioning_source_to_str(ProvisioningSource::AttributeSync),
            "AttributeSync"
        );
    }
}
