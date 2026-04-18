// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `UserService` trait defining the core user management operations.
//!
//! **NIST 800-53 Rev 5:** AC-2 — Account Management
//!
//! This trait abstracts the business logic for user queries and mutations,
//! including listing, fetching, role updates, and suspension. Implementations
//! delegate persistence to a [`UserRepository`](crate::repository::UserRepository).

use pf_common::identity::{Edipi, Role};

use crate::error::ProvisioningError;
use crate::user::{ProvisionedUser, UserStatus};

/// Filter criteria for listing provisioned users.
#[derive(Debug, Clone, Default)]
pub struct UserFilter {
    /// If set, restrict results to users with this status.
    pub status: Option<UserStatus>,
    /// If non-empty, restrict results to users whose `site_id` is in the
    /// set. Used for multi-site admin scope enforcement.
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    pub site_ids: Vec<String>,
}

/// Business-logic interface for user management operations.
///
/// **NIST 800-53 Rev 5:** AC-2 — Account Management
///
/// All mutations (role updates, suspension) MUST be logged as audit events
/// by the implementation.
pub trait UserService: Send + Sync {
    /// List users matching the given filter with pagination.
    ///
    /// Returns a tuple of `(matching_users, total_count)` where `total_count`
    /// is the total number of users matching the filter (before pagination).
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::Repository` on persistence failure.
    fn list_users(
        &self,
        filter: &UserFilter,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<ProvisionedUser>, u64), ProvisioningError>;

    /// Fetch a single user by their EDIPI.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::UserNotFound` if no user has the given EDIPI.
    /// Returns `ProvisioningError::Repository` on persistence failure.
    fn get_user(&self, edipi: &Edipi) -> Result<ProvisionedUser, ProvisioningError>;

    /// Update the roles assigned to a user.
    ///
    /// **NIST 800-53 Rev 5:** AC-2 — Account Management
    ///
    /// The previous roles and new roles SHOULD be logged as an audit event by
    /// the implementation.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::UserNotFound` if the user does not exist.
    /// Returns `ProvisioningError::Repository` on persistence failure.
    fn update_roles(
        &self,
        edipi: &Edipi,
        new_roles: Vec<Role>,
    ) -> Result<ProvisionedUser, ProvisioningError>;

    /// Suspend a user account, preventing further authentication.
    ///
    /// **NIST 800-53 Rev 5:** AC-2(3) — Disable Accounts
    ///
    /// The implementation MUST set the user status to `Suspended`. The caller
    /// is responsible for executing follow-up actions (job purge, session
    /// revocation) based on the deprovisioning module.
    ///
    /// # Errors
    ///
    /// Returns `ProvisioningError::UserNotFound` if the user does not exist.
    /// Returns `ProvisioningError::Repository` on persistence failure.
    fn suspend_user(&self, edipi: &Edipi) -> Result<(), ProvisioningError>;
}
