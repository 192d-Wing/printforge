// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for quota counters and policy override records.
//!
//! Quota counters are stored in `PostgreSQL` with atomic increment.
//! Policy overrides allow per-cost-center or per-user adjustments to
//! default limits.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement

use std::future::Future;

use pf_common::identity::Edipi;
use pf_common::job::CostCenter;
use pf_common::policy::QuotaStatus;

use crate::defaults::DefaultOverrides;
use crate::error::PolicyError;

/// Repository for policy-related persistent state.
///
/// Implementations back this trait with `PostgreSQL` (central) or
/// `SQLite` (edge cache nodes).
pub trait PolicyRepository: Send + Sync {
    /// Retrieve the current quota status for a user in the current billing
    /// period.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::QuotaStorage`] on database errors.
    fn get_quota_status(
        &self,
        user: &Edipi,
    ) -> impl Future<Output = Result<QuotaStatus, PolicyError>> + Send;

    /// Atomically increment the user's page usage counter.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::QuotaStorage`] on database errors.
    fn increment_usage(
        &self,
        user: &Edipi,
        pages: u32,
        color_pages: u32,
    ) -> impl Future<Output = Result<(), PolicyError>> + Send;

    /// Retrieve the default overrides for a given cost center,
    /// falling back to the global defaults if no override exists.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::QuotaStorage`] on database errors.
    fn get_overrides_for_cost_center(
        &self,
        cost_center: &CostCenter,
    ) -> impl Future<Output = Result<DefaultOverrides, PolicyError>> + Send;

    /// Retrieve the quota limit for a user, considering per-user overrides
    /// and cost-center defaults.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::QuotaStorage`] on database errors.
    fn get_quota_limit(
        &self,
        user: &Edipi,
        cost_center: &CostCenter,
    ) -> impl Future<Output = Result<QuotaLimits, PolicyError>> + Send;

    /// Reset all quota counters for the current billing period.
    /// Typically called on the 1st of each month by a scheduled task.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::QuotaStorage`] on database errors.
    fn reset_all_quotas(&self) -> impl Future<Output = Result<u64, PolicyError>> + Send;
}

/// Quota limits for a user in a billing period.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuotaLimits {
    /// Maximum total pages per billing period.
    pub total_pages: u32,
    /// Maximum color pages per billing period.
    pub color_pages: u32,
    /// Burst allowance percentage (e.g., 10 for 10%).
    pub burst_percent: u8,
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            total_pages: 500,
            color_pages: 50,
            burst_percent: 10,
        }
    }
}

/// An in-memory implementation of [`PolicyRepository`] for testing.
#[cfg(test)]
pub mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use pf_common::identity::Edipi;
    use pf_common::job::CostCenter;
    use pf_common::policy::QuotaStatus;

    use super::{PolicyRepository, QuotaLimits};
    use crate::defaults::DefaultOverrides;
    use crate::error::PolicyError;

    /// A mock repository that stores quota state in memory.
    #[derive(Debug)]
    pub struct MockPolicyRepository {
        quotas: Mutex<HashMap<String, QuotaStatus>>,
        overrides: DefaultOverrides,
        limits: QuotaLimits,
    }

    impl MockPolicyRepository {
        /// Create a new mock repository with default values.
        #[must_use]
        pub fn new() -> Self {
            Self {
                quotas: Mutex::new(HashMap::new()),
                overrides: DefaultOverrides::default(),
                limits: QuotaLimits::default(),
            }
        }

        /// Create a mock repository with a pre-set quota for a user.
        #[must_use]
        pub fn with_quota(user_edipi: &str, status: QuotaStatus) -> Self {
            let mut map = HashMap::new();
            map.insert(user_edipi.to_string(), status);
            Self {
                quotas: Mutex::new(map),
                overrides: DefaultOverrides::default(),
                limits: QuotaLimits::default(),
            }
        }
    }

    impl Default for MockPolicyRepository {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PolicyRepository for MockPolicyRepository {
        async fn get_quota_status(&self, user: &Edipi) -> Result<QuotaStatus, PolicyError> {
            let quotas = self.quotas.lock().map_err(|e| {
                PolicyError::QuotaStorage(Box::new(std::io::Error::other(e.to_string())))
            })?;
            Ok(quotas.get(user.as_str()).cloned().unwrap_or(QuotaStatus {
                limit: self.limits.total_pages,
                used: 0,
                color_limit: self.limits.color_pages,
                color_used: 0,
            }))
        }

        async fn increment_usage(
            &self,
            user: &Edipi,
            pages: u32,
            color_pages: u32,
        ) -> Result<(), PolicyError> {
            let mut quotas = self.quotas.lock().map_err(|e| {
                PolicyError::QuotaStorage(Box::new(std::io::Error::other(e.to_string())))
            })?;
            let entry = quotas
                .entry(user.as_str().to_string())
                .or_insert(QuotaStatus {
                    limit: self.limits.total_pages,
                    used: 0,
                    color_limit: self.limits.color_pages,
                    color_used: 0,
                });
            entry.used = entry.used.saturating_add(pages);
            entry.color_used = entry.color_used.saturating_add(color_pages);
            Ok(())
        }

        async fn get_overrides_for_cost_center(
            &self,
            _cost_center: &CostCenter,
        ) -> Result<DefaultOverrides, PolicyError> {
            Ok(self.overrides.clone())
        }

        async fn get_quota_limit(
            &self,
            _user: &Edipi,
            _cost_center: &CostCenter,
        ) -> Result<QuotaLimits, PolicyError> {
            Ok(self.limits.clone())
        }

        async fn reset_all_quotas(&self) -> Result<u64, PolicyError> {
            let mut quotas = self.quotas.lock().map_err(|e| {
                PolicyError::QuotaStorage(Box::new(std::io::Error::other(e.to_string())))
            })?;
            let count = quotas.len() as u64;
            quotas.clear();
            Ok(count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockPolicyRepository;
    use super::*;

    #[tokio::test]
    async fn mock_repo_returns_default_quota() {
        let repo = MockPolicyRepository::new();
        let edipi = Edipi::new("1234567890").unwrap();
        let status = repo.get_quota_status(&edipi).await.unwrap();
        assert_eq!(status.limit, 500);
        assert_eq!(status.used, 0);
    }

    #[tokio::test]
    async fn mock_repo_increments_usage() {
        let repo = MockPolicyRepository::new();
        let edipi = Edipi::new("1234567890").unwrap();
        repo.increment_usage(&edipi, 10, 5).await.unwrap();
        let status = repo.get_quota_status(&edipi).await.unwrap();
        assert_eq!(status.used, 10);
        assert_eq!(status.color_used, 5);
    }

    #[tokio::test]
    async fn mock_repo_resets_quotas() {
        let repo = MockPolicyRepository::new();
        let edipi = Edipi::new("1234567890").unwrap();
        repo.increment_usage(&edipi, 10, 5).await.unwrap();
        let count = repo.reset_all_quotas().await.unwrap();
        assert_eq!(count, 1);
        let status = repo.get_quota_status(&edipi).await.unwrap();
        assert_eq!(status.used, 0);
    }

    #[tokio::test]
    async fn mock_repo_with_preset_quota() {
        let quota = QuotaStatus {
            limit: 100,
            used: 80,
            color_limit: 20,
            color_used: 15,
        };
        let repo = MockPolicyRepository::with_quota("1234567890", quota);
        let edipi = Edipi::new("1234567890").unwrap();
        let status = repo.get_quota_status(&edipi).await.unwrap();
        assert_eq!(status.used, 80);
        assert_eq!(status.color_used, 15);
    }
}
