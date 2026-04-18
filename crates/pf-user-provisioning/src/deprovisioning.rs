// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Account deprovisioning: suspension, job purge, session revocation.
//!
//! **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
//!
//! Deprovisioning in `PrintForge` means suspension, not deletion. When a
//! user is deprovisioned (via `SCIM` deactivate, admin action, or policy):
//!
//! 1. The user's status is set to `Suspended`.
//! 2. All held print jobs are purged.
//! 3. All active sessions/JWTs are revoked (EDIPI added to revocation cache).
//! 4. An audit event is emitted.
//!
//! The user record is retained for audit trail integrity.

use pf_common::identity::Edipi;

use crate::error::ProvisioningError;
use crate::repository::UserRepository;
use crate::user::UserStatus;

/// Actions to be performed by external systems after deprovisioning.
///
/// The caller is responsible for executing these actions against the
/// appropriate services (job queue, auth, etc.).
#[derive(Debug, Clone)]
pub struct DeprovisioningActions {
    /// The EDIPI of the suspended user.
    pub edipi: Edipi,
    /// Whether held jobs should be purged.
    pub purge_held_jobs: bool,
    /// Whether active sessions should be revoked.
    pub revoke_sessions: bool,
}

/// Suspend a user account and return the required follow-up actions.
///
/// **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
///
/// This function:
/// 1. Validates the user exists and is currently active.
/// 2. Sets the user status to `Suspended`.
/// 3. Returns [`DeprovisioningActions`] for the caller to execute.
///
/// # Errors
///
/// Returns `ProvisioningError::UserNotFound` if the EDIPI is not in the repository.
/// Returns `ProvisioningError::Repository` on persistence failure.
pub fn suspend_user(
    repo: &dyn UserRepository,
    edipi: &Edipi,
) -> Result<DeprovisioningActions, ProvisioningError> {
    // Verify user exists.
    let user = repo
        .find_by_edipi(edipi)?
        .ok_or_else(|| ProvisioningError::UserNotFound {
            detail: "cannot suspend nonexistent user".to_string(),
        })?;

    if user.status == UserStatus::Suspended {
        tracing::info!("user is already suspended, returning actions");
        return Ok(DeprovisioningActions {
            edipi: edipi.clone(),
            purge_held_jobs: false,
            revoke_sessions: false,
        });
    }

    // Suspend the user.
    repo.update_status(edipi, UserStatus::Suspended)?;

    tracing::info!("user account suspended");

    Ok(DeprovisioningActions {
        edipi: edipi.clone(),
        purge_held_jobs: true,
        revoke_sessions: true,
    })
}

/// Reactivate a previously suspended user account.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
///
/// # Errors
///
/// Returns `ProvisioningError::UserNotFound` if the EDIPI is not in the repository.
/// Returns `ProvisioningError::Repository` on persistence failure.
pub fn reactivate_user(repo: &dyn UserRepository, edipi: &Edipi) -> Result<(), ProvisioningError> {
    // Verify user exists.
    let _user = repo
        .find_by_edipi(edipi)?
        .ok_or_else(|| ProvisioningError::UserNotFound {
            detail: "cannot reactivate nonexistent user".to_string(),
        })?;

    repo.update_status(edipi, UserStatus::Active)?;

    tracing::info!("user account reactivated");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::InMemoryUserRepository;
    use crate::user::{ProvisionedUser, ProvisioningSource, UserPreferences};
    use chrono::Utc;
    use pf_common::identity::Role;
    use pf_common::job::CostCenter;
    use uuid::Uuid;

    fn test_user() -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new("1234567890").unwrap(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "Test Unit".to_string(),
            roles: vec![Role::User],
            cost_centers: vec![CostCenter::new("CC001", "Test").unwrap()],
            preferences: UserPreferences::default(),
            status: UserStatus::Active,
            provisioning_source: ProvisioningSource::Jit,
            created_at: now,
            updated_at: now,
            last_login_at: Some(now),
        }
    }

    #[test]
    fn nist_ac2_3_suspend_user_sets_status() {
        // NIST 800-53 Rev 5: AC-2(3) — Disable Accounts
        // Evidence: Suspending a user sets their status to Suspended.
        let repo = InMemoryUserRepository::new();
        let user = test_user();
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        let actions = suspend_user(&repo, &edipi).unwrap();

        assert!(actions.purge_held_jobs);
        assert!(actions.revoke_sessions);

        let suspended = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(suspended.status, UserStatus::Suspended);
    }

    #[test]
    fn suspend_nonexistent_user_fails() {
        let repo = InMemoryUserRepository::new();
        let edipi = Edipi::new("9999999999").unwrap();
        let result = suspend_user(&repo, &edipi);
        assert!(matches!(
            result,
            Err(ProvisioningError::UserNotFound { .. })
        ));
    }

    #[test]
    fn suspend_already_suspended_user_is_idempotent() {
        let repo = InMemoryUserRepository::new();
        let user = test_user();
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        let _ = suspend_user(&repo, &edipi).unwrap();

        // Suspend again.
        let actions = suspend_user(&repo, &edipi).unwrap();
        assert!(!actions.purge_held_jobs);
        assert!(!actions.revoke_sessions);
    }

    #[test]
    fn reactivate_suspended_user() {
        let repo = InMemoryUserRepository::new();
        let user = test_user();
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        suspend_user(&repo, &edipi).unwrap();
        reactivate_user(&repo, &edipi).unwrap();

        let reactivated = repo.find_by_edipi(&edipi).unwrap().unwrap();
        assert_eq!(reactivated.status, UserStatus::Active);
    }

    #[test]
    fn reactivate_nonexistent_user_fails() {
        let repo = InMemoryUserRepository::new();
        let edipi = Edipi::new("9999999999").unwrap();
        let result = reactivate_user(&repo, &edipi);
        assert!(matches!(
            result,
            Err(ProvisioningError::UserNotFound { .. })
        ));
    }

    #[test]
    fn nist_ac2_3_deprovisioning_actions_include_job_purge() {
        // NIST 800-53 Rev 5: AC-2(3) — Disable Accounts
        // Evidence: Deprovisioning actions include purging held jobs.
        let repo = InMemoryUserRepository::new();
        let user = test_user();
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        let actions = suspend_user(&repo, &edipi).unwrap();
        assert!(actions.purge_held_jobs);
    }

    #[test]
    fn nist_ac2_3_deprovisioning_actions_include_session_revocation() {
        // NIST 800-53 Rev 5: AC-2(3) — Disable Accounts
        // Evidence: Deprovisioning actions include revoking active sessions.
        let repo = InMemoryUserRepository::new();
        let user = test_user();
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        let actions = suspend_user(&repo, &edipi).unwrap();
        assert!(actions.revoke_sessions);
    }

    #[test]
    fn nist_ac2_suspended_user_record_is_retained() {
        // NIST 800-53 Rev 5: AC-2 — Account Management
        // Evidence: Suspended user record still exists (not deleted).
        let repo = InMemoryUserRepository::new();
        let user = test_user();
        repo.create(&user).unwrap();

        let edipi = Edipi::new("1234567890").unwrap();
        suspend_user(&repo, &edipi).unwrap();

        let found = repo.find_by_edipi(&edipi).unwrap();
        assert!(found.is_some(), "suspended user must not be deleted");
    }
}
