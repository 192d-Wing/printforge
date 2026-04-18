// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for supply chain automation.
//!
//! Includes reorder thresholds, lead times, approval dollar limits,
//! and vendor API connection details.

use secrecy::SecretString;
use serde::Deserialize;

/// Top-level supply configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupplyConfig {
    /// Thresholds that trigger reorder evaluation.
    pub thresholds: ThresholdConfig,

    /// Vendor lead-time assumptions.
    pub lead_time: LeadTimeConfig,

    /// Dollar thresholds for the approval chain.
    pub approval: ApprovalConfig,

    /// Prediction model parameters.
    pub prediction: PredictionConfig,
}

/// Static percentage thresholds for each consumable type.
///
/// A reorder is triggered when the current level falls at or below the
/// configured percentage.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ThresholdConfig {
    /// Black toner reorder threshold (default: 15%).
    pub toner_pct: u8,
    /// Paper reorder threshold (default: 20%).
    pub paper_pct: u8,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            toner_pct: 15,
            paper_pct: 20,
        }
    }
}

/// Estimated vendor lead times in calendar days.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct LeadTimeConfig {
    /// Default lead time if no vendor-specific value is known.
    pub default_days: u32,
    /// Buffer days added to lead time for safety stock.
    pub buffer_days: u32,
}

impl Default for LeadTimeConfig {
    fn default() -> Self {
        Self {
            default_days: 7,
            buffer_days: 3,
        }
    }
}

/// Dollar-amount thresholds controlling the approval chain.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ApprovalConfig {
    /// Orders at or below this value (in cents) are auto-approved.
    pub auto_approve_limit_cents: u64,
    /// Orders above `auto_approve_limit_cents` but at or below this value
    /// require Site Admin approval. Above this requires Fleet Admin.
    pub site_admin_limit_cents: u64,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            auto_approve_limit_cents: 50_000, // $500.00
            site_admin_limit_cents: 500_000,  // $5,000.00
        }
    }
}

/// Parameters for the consumption prediction model.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PredictionConfig {
    /// Number of days in the moving-average window.
    pub window_days: usize,
    /// Minimum number of data points required to produce a prediction.
    pub min_data_points: usize,
}

impl Default for PredictionConfig {
    fn default() -> Self {
        Self {
            window_days: 90,
            min_data_points: 7,
        }
    }
}

/// Connection details for a supply vendor API.
///
/// **Security:** The `api_key` field uses [`SecretString`] so it is never
/// logged or serialized.  NIST 800-53 Rev 5: SC-12, SC-13.
#[derive(Clone, Deserialize)]
pub struct VendorConfig {
    /// Human-readable vendor name (e.g. "HP", "Xerox").
    pub name: String,
    /// Base URL of the vendor ordering API.
    pub base_url: String,
    /// API key — stored as a [`SecretString`] and never logged.
    pub api_key: SecretString,
    /// Vendor-specific lead time override (days). Falls back to
    /// [`LeadTimeConfig::default_days`] if `None`.
    pub lead_time_days: Option<u32>,
}

// Manual Debug impl to prevent accidental secret leakage.
impl std::fmt::Debug for VendorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VendorConfig")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("lead_time_days", &self.lead_time_days)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = SupplyConfig::default();
        assert_eq!(cfg.thresholds.toner_pct, 15);
        assert_eq!(cfg.thresholds.paper_pct, 20);
        assert_eq!(cfg.lead_time.default_days, 7);
        assert_eq!(cfg.approval.auto_approve_limit_cents, 50_000);
    }

    #[test]
    fn vendor_config_debug_redacts_api_key() {
        let vc = VendorConfig {
            name: "TestVendor".to_string(),
            base_url: "https://example.com".to_string(),
            api_key: SecretString::from("super-secret-key".to_string()),
            lead_time_days: Some(5),
        };
        let debug = format!("{vc:?}");
        assert!(!debug.contains("super-secret-key"));
        assert!(debug.contains("[REDACTED]"));
    }
}
