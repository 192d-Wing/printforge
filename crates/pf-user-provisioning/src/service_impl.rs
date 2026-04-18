// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default [`UserService`] implementation backed by a [`UserRepository`].
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! This implementation delegates all persistence to a boxed
//! [`UserRepository`](crate::repository::UserRepository) and applies
//! business rules (e.g., not-found errors, role update timestamps).

use chrono::Utc;
use pf_common::identity::{Edipi, Role};

use crate::error::ProvisioningError;
use crate::repository::UserRepository;
use crate::service::{UserFilter, UserService};
use crate::user::{ProvisionedUser, UserStatus};

/// Default implementation of [`UserService`] backed by a [`UserRepository`].
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
pub struct DefaultUserService {
    repo: Box<dyn UserRepository>,
}

impl DefaultUserService {
    /// Create a new `DefaultUserService` wrapping the given repository.
    #[must_use]
    pub fn new(repo: Box<dyn UserRepository>) -> Self {
        Self { repo }
    }
}

impl UserService for DefaultUserService {
    /// List users matching the filter with pagination.
    ///
    /// When a status filter is provided, delegates to
    /// [`UserRepository::list_by_status`]. When no filter is set, retrieves
    /// both active and suspended users and merges the results.
    fn list_users(
        &self,
        filter: &UserFilter,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<ProvisionedUser>, u64), ProvisioningError> {
        let all_matching = if let Some(status) = filter.status {
            self.repo.list_by_status(status)?
        } else {
            // No status filter — fetch both active and suspended users.
            let mut users = self.repo.list_by_status(UserStatus::Active)?;
            let suspended = self.repo.list_by_status(UserStatus::Suspended)?;
            users.extend(suspended);
            users
        };

        let total = u64::try_from(all_matching.len()).unwrap_or(u64::MAX);

        let page: Vec<ProvisionedUser> = all_matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        Ok((page, total))
    }

    /// Fetch a single user by EDIPI, returning an error if not found.
    fn get_user(&self, edipi: &Edipi) -> Result<ProvisionedUser, ProvisioningError> {
        self.repo
            .find_by_edipi(edipi)?
            .ok_or_else(|| ProvisioningError::UserNotFound {
                detail: "user not found by EDIPI".to_string(),
            })
    }

    /// Update the roles assigned to a user.
    ///
    /// **NIST 800-53 Rev 5:** AC-2 — Account Management
    ///
    /// Fetches the user, replaces their role list, updates `updated_at`, and
    /// persists via the repository.
    fn update_roles(
        &self,
        edipi: &Edipi,
        new_roles: Vec<Role>,
    ) -> Result<ProvisionedUser, ProvisioningError> {
        let mut user =
            self.repo
                .find_by_edipi(edipi)?
                .ok_or_else(|| ProvisioningError::UserNotFound {
                    detail: "user not found for role update".to_string(),
                })?;

        tracing::info!(
            previous_roles = ?user.roles,
            new_roles = ?new_roles,
            "updating user roles"
        );

        user.roles = new_roles;
        user.updated_at = Utc::now();
        self.repo.update(&user)?;
        Ok(user)
    }

    /// Suspend a user account.
    ///
    /// **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
    fn suspend_user(&self, edipi: &Edipi) -> Result<(), ProvisioningError> {
        // Verify the user exists before attempting suspension.
        let _user =
            self.repo
                .find_by_edipi(edipi)?
                .ok_or_else(|| ProvisioningError::UserNotFound {
                    detail: "user not found for suspension".to_string(),
                })?;

        self.repo.update_status(edipi, UserStatus::Suspended)?;
        tracing::info!("user account suspended via UserService");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryUserRepository;
    use crate::service::UserFilter;
    use crate::user::{ProvisioningSource, UserPreferences};
    use pf_common::identity::Role;
    use pf_common::job::CostCenter;
    use uuid::Uuid;

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

    fn service_with_users(users: &[ProvisionedUser]) -> DefaultUserService {
        let repo = InMemoryUserRepository::new();
        for user in users {
            repo.create(user).unwrap();
        }
        DefaultUserService::new(Box::new(repo))
    }

    // --- list_users tests ---

    #[test]
    fn list_users_returns_all_matching_users() {
        let alice = test_user("1234567890");
        let bob = test_user("0987654321");
        let svc = service_with_users(&[alice, bob]);

        let filter = UserFilter::default();
        let (users, total) = svc.list_users(&filter, 100, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn list_users_filters_by_status() {
        let active_user = test_user("1234567890");
        let mut suspended_user = test_user("0987654321");
        suspended_user.status = UserStatus::Suspended;
        let svc = service_with_users(&[active_user, suspended_user]);

        let filter = UserFilter {
            status: Some(UserStatus::Active),
        };
        let (users, total) = svc.list_users(&filter, 100, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].status, UserStatus::Active);
    }

    #[test]
    fn list_users_pagination_applies_limit_and_offset() {
        let user1 = test_user("1234567890");
        let user2 = test_user("0987654321");
        let user3 = test_user("1111111111");
        let svc = service_with_users(&[user1, user2, user3]);

        let filter = UserFilter::default();

        // Page 1: offset 0, limit 2
        let (page1, total) = svc.list_users(&filter, 2, 0).unwrap();
        assert_eq!(total, 3);
        assert_eq!(page1.len(), 2);

        // Page 2: offset 2, limit 2
        let (page2, _) = svc.list_users(&filter, 2, 2).unwrap();
        assert_eq!(page2.len(), 1);
    }

    // --- get_user tests ---

    #[test]
    fn get_user_by_edipi_returns_correct_user() {
        let user = test_user("1234567890");
        let svc = service_with_users(&[user]);

        let edipi = Edipi::new("1234567890").unwrap();
        let found = svc.get_user(&edipi).unwrap();
        assert_eq!(found.edipi.as_str(), "1234567890");
        assert_eq!(found.display_name, "DOE, TEST T.");
    }

    #[test]
    fn get_nonexistent_user_returns_error() {
        let svc = service_with_users(&[]);

        let edipi = Edipi::new("9999999999").unwrap();
        let result = svc.get_user(&edipi);
        assert!(matches!(
            result,
            Err(ProvisioningError::UserNotFound { .. })
        ));
    }

    // --- update_roles tests ---

    #[test]
    fn update_roles_persists_new_roles() {
        let user = test_user("1234567890");
        let svc = service_with_users(&[user]);

        let edipi = Edipi::new("1234567890").unwrap();
        let new_roles = vec![Role::User, Role::FleetAdmin];
        let updated = svc.update_roles(&edipi, new_roles.clone()).unwrap();
        assert_eq!(updated.roles, new_roles);

        // Verify persistence through a fresh get.
        let fetched = svc.get_user(&edipi).unwrap();
        assert_eq!(fetched.roles, vec![Role::User, Role::FleetAdmin]);
    }

    #[test]
    fn update_roles_nonexistent_user_returns_error() {
        let svc = service_with_users(&[]);

        let edipi = Edipi::new("9999999999").unwrap();
        let result = svc.update_roles(&edipi, vec![Role::User]);
        assert!(matches!(
            result,
            Err(ProvisioningError::UserNotFound { .. })
        ));
    }

    // --- suspend_user tests ---

    #[test]
    fn suspend_user_marks_as_inactive() {
        let user = test_user("1234567890");
        let svc = service_with_users(&[user]);

        let edipi = Edipi::new("1234567890").unwrap();
        svc.suspend_user(&edipi).unwrap();

        let fetched = svc.get_user(&edipi).unwrap();
        assert_eq!(fetched.status, UserStatus::Suspended);
    }

    #[test]
    fn suspend_nonexistent_user_returns_error() {
        let svc = service_with_users(&[]);

        let edipi = Edipi::new("9999999999").unwrap();
        let result = svc.suspend_user(&edipi);
        assert!(matches!(
            result,
            Err(ProvisioningError::UserNotFound { .. })
        ));
    }

    // --- NIST compliance evidence tests ---

    #[test]
    fn nist_ac2_update_roles_changes_user_roles() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Role updates are persisted and retrievable.
        let user = test_user("1234567890");
        let svc = service_with_users(&[user]);

        let edipi = Edipi::new("1234567890").unwrap();
        let updated = svc
            .update_roles(&edipi, vec![Role::FleetAdmin, Role::Auditor])
            .unwrap();
        assert!(updated.roles.contains(&Role::FleetAdmin));
        assert!(updated.roles.contains(&Role::Auditor));
        assert!(!updated.roles.contains(&Role::User));
    }

    #[test]
    fn nist_ac2_3_suspend_user_prevents_active_status() {
        // NIST 800-53 Rev 5: AC-2(3) — Disable Accounts
        // Evidence: Suspended user is no longer in Active status.
        let user = test_user("1234567890");
        let svc = service_with_users(&[user]);

        let edipi = Edipi::new("1234567890").unwrap();
        svc.suspend_user(&edipi).unwrap();

        let fetched = svc.get_user(&edipi).unwrap();
        assert_eq!(fetched.status, UserStatus::Suspended);
        assert!(!fetched.is_active());
    }

    #[test]
    fn nist_ac2_suspended_user_still_exists_in_repository() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Suspended user record is retained (not deleted) for audit.
        let user = test_user("1234567890");
        let svc = service_with_users(&[user]);

        let edipi = Edipi::new("1234567890").unwrap();
        svc.suspend_user(&edipi).unwrap();

        // User is still retrievable after suspension.
        let result = svc.get_user(&edipi);
        assert!(result.is_ok());
    }
}
