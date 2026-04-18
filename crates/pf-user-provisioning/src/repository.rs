// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for user persistence.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! Defines the persistence interface for provisioned users. Implementations
//! are provided for `PostgreSQL` (production) and in-memory (testing).
//! User records are never hard-deleted; only soft-deletion (suspension) is
//! permitted to preserve audit trail integrity.

use pf_common::identity::Edipi;

use crate::error::ProvisioningError;
use crate::user::{ProvisionedUser, UserStatus};

/// Persistence interface for [`ProvisionedUser`] records.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management, AU-9 — Protection of Audit Info
///
/// Implementations MUST:
/// - Never implement hard-delete (only status changes to `Suspended`)
/// - Log all mutations as audit events
/// - Validate that EDIPI uniqueness is enforced
pub trait UserRepository: Send + Sync {
    /// Look up a user by their EDIPI.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::Repository` on database failure.
    fn find_by_edipi(&self, edipi: &Edipi) -> Result<Option<ProvisionedUser>, ProvisioningError>;

    /// Persist a new user record.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::Repository` if the EDIPI already exists
    /// or on database failure.
    fn create(&self, user: &ProvisionedUser) -> Result<(), ProvisioningError>;

    /// Update an existing user record.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::UserNotFound` if the user does not exist.
    /// Returns `ProvisioningError::Repository` on database failure.
    fn update(&self, user: &ProvisionedUser) -> Result<(), ProvisioningError>;

    /// Update only the user's status field.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::UserNotFound` if the user does not exist.
    /// Returns `ProvisioningError::Repository` on database failure.
    fn update_status(&self, edipi: &Edipi, status: UserStatus) -> Result<(), ProvisioningError>;

    /// List all users with a given status.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::Repository` on database failure.
    fn list_by_status(&self, status: UserStatus)
    -> Result<Vec<ProvisionedUser>, ProvisioningError>;
}

/// In-memory repository for testing.
///
/// NOT for production use. Provides a simple `Vec`-backed store.
#[derive(Debug, Default)]
pub struct InMemoryUserRepository {
    users: std::sync::Mutex<Vec<ProvisionedUser>>,
}

impl InMemoryUserRepository {
    /// Create a new empty in-memory repository.
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl UserRepository for InMemoryUserRepository {
    fn find_by_edipi(&self, edipi: &Edipi) -> Result<Option<ProvisionedUser>, ProvisioningError> {
        let users = self
            .users
            .lock()
            .map_err(|e| ProvisioningError::Repository {
                detail: format!("lock poisoned: {e}"),
            })?;
        Ok(users
            .iter()
            .find(|u| u.edipi.as_str() == edipi.as_str())
            .cloned())
    }

    fn create(&self, user: &ProvisionedUser) -> Result<(), ProvisioningError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| ProvisioningError::Repository {
                detail: format!("lock poisoned: {e}"),
            })?;
        if users
            .iter()
            .any(|u| u.edipi.as_str() == user.edipi.as_str())
        {
            return Err(ProvisioningError::Repository {
                detail: "EDIPI already exists".to_string(),
            });
        }
        users.push(user.clone());
        Ok(())
    }

    fn update(&self, user: &ProvisionedUser) -> Result<(), ProvisioningError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| ProvisioningError::Repository {
                detail: format!("lock poisoned: {e}"),
            })?;
        let existing = users
            .iter_mut()
            .find(|u| u.edipi.as_str() == user.edipi.as_str())
            .ok_or_else(|| ProvisioningError::UserNotFound {
                detail: "user not found for update".to_string(),
            })?;
        *existing = user.clone();
        Ok(())
    }

    fn update_status(&self, edipi: &Edipi, status: UserStatus) -> Result<(), ProvisioningError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| ProvisioningError::Repository {
                detail: format!("lock poisoned: {e}"),
            })?;
        let existing = users
            .iter_mut()
            .find(|u| u.edipi.as_str() == edipi.as_str())
            .ok_or_else(|| ProvisioningError::UserNotFound {
                detail: "user not found for status update".to_string(),
            })?;
        existing.status = status;
        Ok(())
    }

    fn list_by_status(
        &self,
        status: UserStatus,
    ) -> Result<Vec<ProvisionedUser>, ProvisioningError> {
        let users = self
            .users
            .lock()
            .map_err(|e| ProvisioningError::Repository {
                detail: format!("lock poisoned: {e}"),
            })?;
        Ok(users
            .iter()
            .filter(|u| u.status == status)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::{ProvisioningSource, UserPreferences};
    use chrono::Utc;
    use pf_common::identity::Role;
    use pf_common::job::CostCenter;
    use uuid::Uuid;

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
    fn create_and_find_user() {
        let repo = InMemoryUserRepository::new();
        let user = test_user("1234567890");
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().display_name, "DOE, TEST T.");
    }

    #[test]
    fn find_nonexistent_returns_none() {
        let repo = InMemoryUserRepository::new();
        let edipi = Edipi::new("9999999999").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn create_duplicate_fails() {
        let repo = InMemoryUserRepository::new();
        let user = test_user("1234567890");
        repo.create(&user).unwrap();
        let result = repo.create(&user);
        assert!(result.is_err());
    }

    #[test]
    fn update_existing_user() {
        let repo = InMemoryUserRepository::new();
        let mut user = test_user("1234567890");
        repo.create(&user).unwrap();

        user.display_name = "SMITH, UPDATED U.".to_string();
        repo.update(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        let found = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(found.display_name, "SMITH, UPDATED U.");
    }

    #[test]
    fn update_nonexistent_fails() {
        let repo = InMemoryUserRepository::new();
        let user = test_user("1234567890");
        let result = repo.update(&user);
        assert!(result.is_err());
    }

    #[test]
    fn update_status_suspends_user() {
        let repo = InMemoryUserRepository::new();
        let user = test_user("1234567890");
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        repo.update_status(&edipi, UserStatus::Suspended).unwrap();

        let found = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(found.status, UserStatus::Suspended);
    }

    #[test]
    fn list_by_status_filters_correctly() {
        let repo = InMemoryUserRepository::new();

        let user1 = test_user("1234567890");
        let mut user2 = test_user("0987654321");
        user2.status = UserStatus::Suspended;

        repo.create(&user1).unwrap();
        repo.create(&user2).unwrap();

        let active = repo.list_by_status(UserStatus::Active).unwrap();
        assert_eq!(active.len(), 1);

        let suspended = repo.list_by_status(UserStatus::Suspended).unwrap();
        assert_eq!(suspended.len(), 1);
    }

    #[test]
    fn nist_ac2_user_records_are_never_deleted() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: The repository trait does not expose a delete method.
        // Users can only be suspended (status change), not removed.
        let repo = InMemoryUserRepository::new();
        let user = test_user("1234567890");
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        repo.update_status(&edipi, UserStatus::Suspended).unwrap();

        // User still exists after suspension.
        let found = repo.find_by_edipi(&edipi).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().status, UserStatus::Suspended);
    }
}
