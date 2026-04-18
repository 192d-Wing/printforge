// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! HP Supply Delivery API client.
//!
//! Implements the [`SupplyVendor`] trait for ordering consumables through
//! the HP Supply Delivery API. HTTP calls are currently stubbed — the
//! implementation logs what would be sent and returns placeholder responses.
//!
//! **Security:** API credentials use [`secrecy::SecretString`] and are
//! never logged or included in debug output.
//! **NIST 800-53 Rev 5:** SC-12, SC-13 — cryptographic key management
//! for vendor API credentials.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::error::SupplyError;
use crate::monitoring::ConsumableKind;
use crate::reorder::ReorderRequest;
use crate::vendor::{OrderLineItem, SupplyVendor, VendorOrder, VendorOrderStatus};

/// A catalog entry representing an available supply for a printer model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// Vendor part number.
    pub part_number: String,
    /// Human-readable description.
    pub description: String,
    /// Which consumable type this entry covers.
    pub consumable: ConsumableKind,
    /// Estimated unit price in cents.
    pub unit_price_cents: u64,
}

/// Configuration for the HP Supply Delivery API client.
///
/// **Security:** The `api_key` field uses [`SecretString`] and is redacted
/// in `Debug` output. NIST 800-53 Rev 5: SC-12.
#[derive(Clone, Deserialize)]
pub struct HpConfig {
    /// Base URL of the HP Supply Delivery API.
    pub base_url: String,
    /// API key for authentication.
    pub api_key: SecretString,
    /// HP customer account identifier.
    pub account_id: String,
}

impl std::fmt::Debug for HpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("account_id", &self.account_id)
            .finish()
    }
}

/// HP Supply Delivery API client.
pub struct HpSupplyClient {
    config: HpConfig,
}

impl HpSupplyClient {
    /// Create a new HP Supply Delivery API client.
    #[must_use]
    pub fn new(config: HpConfig) -> Self {
        Self { config }
    }

    /// Return the vendor-specific part number for a given consumable and
    /// printer model, if known.
    #[must_use]
    pub fn map_part_number(model: &str, consumable: &ConsumableKind) -> Option<&'static str> {
        match (model, consumable) {
            ("HP LaserJet Pro M404", ConsumableKind::TonerBlack) => Some("CF258X"),
            ("HP LaserJet Pro M404", ConsumableKind::Paper) => Some("HPL0S55A"),
            ("HP Color LaserJet M455", ConsumableKind::TonerBlack) => Some("W2040X"),
            ("HP Color LaserJet M455", ConsumableKind::TonerCyan) => Some("W2041X"),
            ("HP Color LaserJet M455", ConsumableKind::TonerMagenta) => Some("W2042X"),
            ("HP Color LaserJet M455", ConsumableKind::TonerYellow) => Some("W2043X"),
            ("HP LaserJet Enterprise M610", ConsumableKind::TonerBlack) => Some("W1470X"),
            _ => None,
        }
    }

    /// Return the catalog of available supplies for a printer model.
    ///
    /// This is a stub that returns sample data for known HP printer models.
    #[must_use]
    pub fn get_catalog(model: &str) -> Vec<CatalogEntry> {
        match model {
            "HP LaserJet Pro M404" => vec![
                CatalogEntry {
                    part_number: "CF258X".to_string(),
                    description: "HP 58X High Yield Black Toner".to_string(),
                    consumable: ConsumableKind::TonerBlack,
                    unit_price_cents: 18_999,
                },
                CatalogEntry {
                    part_number: "HPL0S55A".to_string(),
                    description: "HP Laser Paper, 500 sheets".to_string(),
                    consumable: ConsumableKind::Paper,
                    unit_price_cents: 1_299,
                },
            ],
            "HP Color LaserJet M455" => vec![
                CatalogEntry {
                    part_number: "W2040X".to_string(),
                    description: "HP 416X High Yield Black Toner".to_string(),
                    consumable: ConsumableKind::TonerBlack,
                    unit_price_cents: 17_999,
                },
                CatalogEntry {
                    part_number: "W2041X".to_string(),
                    description: "HP 416X High Yield Cyan Toner".to_string(),
                    consumable: ConsumableKind::TonerCyan,
                    unit_price_cents: 21_999,
                },
                CatalogEntry {
                    part_number: "W2042X".to_string(),
                    description: "HP 416X High Yield Magenta Toner".to_string(),
                    consumable: ConsumableKind::TonerMagenta,
                    unit_price_cents: 21_999,
                },
                CatalogEntry {
                    part_number: "W2043X".to_string(),
                    description: "HP 416X High Yield Yellow Toner".to_string(),
                    consumable: ConsumableKind::TonerYellow,
                    unit_price_cents: 21_999,
                },
            ],
            _ => Vec::new(),
        }
    }
}

impl SupplyVendor for HpSupplyClient {
    async fn submit_order(
        &self,
        request: &ReorderRequest,
        line_items: &[OrderLineItem],
    ) -> Result<VendorOrder, SupplyError> {
        info!(
            vendor = "HP",
            reorder_id = %request.id,
            item_count = line_items.len(),
            base_url = %self.config.base_url,
            "stubbed HP Supply Delivery API order submission"
        );

        // Stub: generate a placeholder vendor order ID.
        let vendor_order_id = format!("HP-{}", Uuid::now_v7());

        Ok(VendorOrder {
            reorder_id: request.id,
            vendor_order_id,
            vendor_name: self.vendor_name().to_string(),
            estimated_delivery_days: Some(5),
        })
    }

    async fn check_order_status(
        &self,
        vendor_order_id: &str,
    ) -> Result<VendorOrderStatus, SupplyError> {
        info!(
            vendor = "HP",
            vendor_order_id = vendor_order_id,
            "stubbed HP order status check"
        );

        // Stub: always return Accepted.
        Ok(VendorOrderStatus::Accepted)
    }

    async fn cancel_order(&self, vendor_order_id: &str) -> Result<(), SupplyError> {
        info!(
            vendor = "HP",
            vendor_order_id = vendor_order_id,
            "stubbed HP order cancellation"
        );

        Ok(())
    }

    fn vendor_name(&self) -> &'static str {
        "HP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorder::{ReorderStatus, ReorderTrigger};

    fn test_config() -> HpConfig {
        HpConfig {
            base_url: "https://api.hp.example.com/supply/v1".to_string(),
            api_key: SecretString::from("hp-test-api-key-12345".to_string()),
            account_id: "HP-ACCT-001".to_string(),
        }
    }

    fn test_reorder_request() -> ReorderRequest {
        ReorderRequest {
            id: Uuid::now_v7(),
            printer_id: pf_common::fleet::PrinterId::new("PRN-0001").unwrap(),
            consumable: ConsumableKind::TonerBlack,
            trigger: ReorderTrigger::Threshold,
            current_level_pct: 10,
            estimated_cost_cents: Some(18_999),
            status: ReorderStatus::Approved,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn hp_config_debug_redacts_api_key() {
        let cfg = test_config();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("hp-test-api-key-12345"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn hp_config_serde_roundtrip() {
        let json = serde_json::json!({
            "base_url": "https://api.hp.example.com/supply/v1",
            "api_key": "hp-key",
            "account_id": "HP-ACCT-001"
        });
        let cfg: HpConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.base_url, "https://api.hp.example.com/supply/v1");
        assert_eq!(cfg.account_id, "HP-ACCT-001");
    }

    #[tokio::test]
    async fn hp_submit_order_produces_valid_vendor_order() {
        let client = HpSupplyClient::new(test_config());
        let request = test_reorder_request();
        let items = vec![OrderLineItem {
            consumable: ConsumableKind::TonerBlack,
            quantity: 1,
            part_number: Some("CF258X".to_string()),
        }];

        let order = client.submit_order(&request, &items).await.unwrap();
        assert_eq!(order.vendor_name, "HP");
        assert_eq!(order.reorder_id, request.id);
        assert!(order.vendor_order_id.starts_with("HP-"));
        assert_eq!(order.estimated_delivery_days, Some(5));
    }

    #[tokio::test]
    async fn hp_check_order_status_returns_accepted() {
        let client = HpSupplyClient::new(test_config());
        let status = client.check_order_status("HP-TEST-001").await.unwrap();
        assert_eq!(status, VendorOrderStatus::Accepted);
    }

    #[tokio::test]
    async fn hp_cancel_order_succeeds() {
        let client = HpSupplyClient::new(test_config());
        let result = client.cancel_order("HP-TEST-001").await;
        assert!(result.is_ok());
    }

    #[test]
    fn hp_catalog_returns_entries_for_known_model() {
        let catalog = HpSupplyClient::get_catalog("HP LaserJet Pro M404");
        assert!(!catalog.is_empty());
        assert!(catalog.iter().any(|e| e.part_number == "CF258X"));
    }

    #[test]
    fn hp_catalog_returns_empty_for_unknown_model() {
        let catalog = HpSupplyClient::get_catalog("Unknown Printer 9000");
        assert!(catalog.is_empty());
    }

    #[test]
    fn hp_part_number_mapping_for_known_model() {
        let part = HpSupplyClient::map_part_number(
            "HP LaserJet Pro M404",
            &ConsumableKind::TonerBlack,
        );
        assert_eq!(part, Some("CF258X"));
    }

    #[test]
    fn hp_part_number_mapping_returns_none_for_unknown() {
        let part = HpSupplyClient::map_part_number(
            "Unknown Printer",
            &ConsumableKind::TonerBlack,
        );
        assert!(part.is_none());
    }

    #[test]
    fn hp_vendor_name() {
        let client = HpSupplyClient::new(test_config());
        assert_eq!(client.vendor_name(), "HP");
    }
}
