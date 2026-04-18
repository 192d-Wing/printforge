// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration types for `PrintForge` cost accounting.
//!
//! Defines the base cost rates, surcharges, and discount percentages
//! used by the cost model to calculate per-job costs.

use serde::{Deserialize, Serialize};

/// Top-level accounting configuration.
///
/// Contains the default cost table applied to all installations
/// unless overridden by a per-installation cost table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountingConfig {
    /// Default cost table used when no installation-specific override exists.
    pub default_cost_table: CostTableConfig,

    /// Default monthly page quota per user.
    pub default_monthly_page_quota: u32,

    /// Default monthly color page quota per user.
    pub default_monthly_color_quota: u32,

    /// Day of the month on which quotas reset (1-28).
    pub quota_reset_day: u8,

    /// Number of years to retain financial data (`DoD` 5015.02 requires 7).
    pub retention_years: u16,
}

impl Default for AccountingConfig {
    fn default() -> Self {
        Self {
            default_cost_table: CostTableConfig::default(),
            default_monthly_page_quota: 500,
            default_monthly_color_quota: 100,
            quota_reset_day: 1,
            retention_years: 7,
        }
    }
}

/// Cost rates and surcharges used to calculate per-job costs.
///
/// All monetary values are in US cents (integer) to avoid floating-point
/// rounding issues in financial calculations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTableConfig {
    /// Base cost per page in cents (grayscale, letter, simplex).
    pub base_cost_cents: u32,

    /// Additional cost per page for color printing, in cents.
    pub color_surcharge_cents: u32,

    /// Discount percentage for duplex printing (0-100).
    /// Applied as: `cost * (100 - duplex_discount_pct) / 100`.
    pub duplex_discount_pct: u8,

    /// Surcharge per page for legal-size media, in cents.
    pub legal_surcharge_cents: u32,

    /// Surcharge per page for ledger-size media, in cents.
    pub ledger_surcharge_cents: u32,

    /// Surcharge per page for A3 media, in cents.
    pub a3_surcharge_cents: u32,

    /// Surcharge per page for A4 media, in cents.
    pub a4_surcharge_cents: u32,

    /// Surcharge per page for stapling finishing, in cents.
    pub staple_surcharge_cents: u32,

    /// Surcharge per page for hole-punch finishing, in cents.
    pub punch_surcharge_cents: u32,
}

impl Default for CostTableConfig {
    fn default() -> Self {
        Self {
            base_cost_cents: 3,
            color_surcharge_cents: 12,
            duplex_discount_pct: 25,
            legal_surcharge_cents: 1,
            ledger_surcharge_cents: 3,
            a3_surcharge_cents: 3,
            a4_surcharge_cents: 0,
            staple_surcharge_cents: 1,
            punch_surcharge_cents: 1,
        }
    }
}

/// Error type for configuration loading failures.
#[derive(Debug)]
pub struct ConfigError {
    /// The environment variable name that caused the error.
    pub var: String,
    /// Human-readable description of the parse failure.
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid value for {}: {}", self.var, self.message)
    }
}

impl std::error::Error for ConfigError {}

impl AccountingConfig {
    /// Constructs an [`AccountingConfig`] by reading environment variables
    /// with the `PF_ACC_` prefix. Falls back to [`Default`] values for any
    /// variable that is not set.
    ///
    /// # Environment Variables
    ///
    /// | Variable | Type | Description |
    /// |---|---|---|
    /// | `PF_ACC_BASE_COST_PER_PAGE_CENTS` | `u32` | Base cost per page (grayscale) |
    /// | `PF_ACC_COLOR_SURCHARGE_CENTS` | `u32` | Additional cost per page for color |
    /// | `PF_ACC_DUPLEX_DISCOUNT_PCT` | `u8` | Discount percentage for duplex (0-100) |
    /// | `PF_ACC_MONTHLY_PAGE_QUOTA` | `u32` | Default monthly page quota per user |
    /// | `PF_ACC_MONTHLY_COLOR_QUOTA` | `u32` | Default monthly color page quota per user |
    /// | `PF_ACC_QUOTA_RESET_DAY` | `u8` | Day of month for quota reset (1-28) |
    /// | `PF_ACC_RETENTION_YEARS` | `u16` | Number of years to retain financial data |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if an environment variable is set but cannot
    /// be parsed to the expected type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();

        if let Ok(val) = std::env::var("PF_ACC_BASE_COST_PER_PAGE_CENTS") {
            cfg.default_cost_table.base_cost_cents = val.parse().map_err(|e| ConfigError {
                var: "PF_ACC_BASE_COST_PER_PAGE_CENTS".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_ACC_COLOR_SURCHARGE_CENTS") {
            cfg.default_cost_table.color_surcharge_cents =
                val.parse().map_err(|e| ConfigError {
                    var: "PF_ACC_COLOR_SURCHARGE_CENTS".to_string(),
                    message: format!("{e}"),
                })?;
        }

        if let Ok(val) = std::env::var("PF_ACC_DUPLEX_DISCOUNT_PCT") {
            cfg.default_cost_table.duplex_discount_pct =
                val.parse().map_err(|e| ConfigError {
                    var: "PF_ACC_DUPLEX_DISCOUNT_PCT".to_string(),
                    message: format!("{e}"),
                })?;
        }

        if let Ok(val) = std::env::var("PF_ACC_MONTHLY_PAGE_QUOTA") {
            cfg.default_monthly_page_quota = val.parse().map_err(|e| ConfigError {
                var: "PF_ACC_MONTHLY_PAGE_QUOTA".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_ACC_MONTHLY_COLOR_QUOTA") {
            cfg.default_monthly_color_quota = val.parse().map_err(|e| ConfigError {
                var: "PF_ACC_MONTHLY_COLOR_QUOTA".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_ACC_QUOTA_RESET_DAY") {
            cfg.quota_reset_day = val.parse().map_err(|e| ConfigError {
                var: "PF_ACC_QUOTA_RESET_DAY".to_string(),
                message: format!("{e}"),
            })?;
        }

        if let Ok(val) = std::env::var("PF_ACC_RETENTION_YEARS") {
            cfg.retention_years = val.parse().map_err(|e| ConfigError {
                var: "PF_ACC_RETENTION_YEARS".to_string(),
                message: format!("{e}"),
            })?;
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_accounting_config_has_sane_values() {
        let config = AccountingConfig::default();
        assert_eq!(config.default_monthly_page_quota, 500);
        assert_eq!(config.default_monthly_color_quota, 100);
        assert_eq!(config.quota_reset_day, 1);
        assert_eq!(config.retention_years, 7);
    }

    #[test]
    fn default_cost_table_has_positive_base() {
        let table = CostTableConfig::default();
        assert!(table.base_cost_cents > 0);
        assert!(table.duplex_discount_pct <= 100);
    }

    #[test]
    fn from_env_returns_defaults_when_no_vars_set() {
        // When none of the PF_ACC_* vars are set, from_env falls back to defaults.
        // This test relies on the CI/test environment NOT having these set.
        // We cannot call set_var/remove_var because edition 2024 marks them unsafe
        // and the crate uses #![forbid(unsafe_code)].
        let cfg = AccountingConfig::from_env().expect("from_env should succeed with defaults");
        let default_cfg = AccountingConfig::default();
        assert_eq!(
            cfg.default_cost_table.base_cost_cents,
            default_cfg.default_cost_table.base_cost_cents
        );
        assert_eq!(
            cfg.default_cost_table.color_surcharge_cents,
            default_cfg.default_cost_table.color_surcharge_cents
        );
        assert_eq!(cfg.default_monthly_page_quota, default_cfg.default_monthly_page_quota);
        assert_eq!(cfg.retention_years, default_cfg.retention_years);
    }

    #[test]
    fn config_error_displays_var_and_message() {
        let err = ConfigError {
            var: "PF_ACC_BASE_COST_PER_PAGE_CENTS".to_string(),
            message: "invalid digit found in string".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("PF_ACC_BASE_COST_PER_PAGE_CENTS"));
        assert!(msg.contains("invalid digit"));
    }
}
