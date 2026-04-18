// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Lexmark Cartridge Collection API client.
//!
//! Implements the [`SupplyVendor`] trait for ordering consumables through
//! the Lexmark Cartridge Collection API. HTTP calls are currently stubbed —
//! the implementation logs what would be sent and returns placeholder
//! responses.
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

/// A catalog entry representing an available Lexmark supply.
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

/// Configuration for the Lexmark Cartridge Collection API client.
///
/// **Security:** The `api_key` field uses [`SecretString`] and is redacted
/// in `Debug` output. NIST 800-53 Rev 5: SC-12.
#[derive(Clone, Deserialize)]
pub struct LexmarkConfig {
    /// Base URL of the Lexmark Cartridge Collection API.
    pub base_url: String,
    /// API key for authentication.
    pub api_key: SecretString,
    /// Lexmark dealer/reseller code.
    pub dealer_code: String,
}

impl std::fmt::Debug for LexmarkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LexmarkConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("dealer_code", &self.dealer_code)
            .finish()
    }
}

/// Lexmark Cartridge Collection API client.
pub struct LexmarkSupplyClient {
    config: LexmarkConfig,
}

impl LexmarkSupplyClient {
    /// Create a new Lexmark Cartridge Collection API client.
    #[must_use]
    pub fn new(config: LexmarkConfig) -> Self {
        Self { config }
    }

    /// Return the vendor-specific part number for a given consumable and
    /// printer model, if known.
    #[must_use]
    pub fn map_part_number(model: &str, consumable: &ConsumableKind) -> Option<&'static str> {
        match (model, consumable) {
            ("Lexmark MS621", ConsumableKind::TonerBlack) => Some("56F1H00"),
            ("Lexmark CS521", ConsumableKind::TonerBlack) => Some("78C1UK0"),
            ("Lexmark CS521", ConsumableKind::TonerCyan) => Some("78C1UC0"),
            ("Lexmark CS521", ConsumableKind::TonerMagenta) => Some("78C1UM0"),
            ("Lexmark CS521", ConsumableKind::TonerYellow) => Some("78C1UY0"),
            ("Lexmark MX722", ConsumableKind::TonerBlack) => Some("58D1H00"),
            _ => None,
        }
    }

    /// Return the catalog of available supplies for a printer model.
    ///
    /// This is a stub that returns sample data for known Lexmark printer models.
    #[must_use]
    pub fn get_catalog(model: &str) -> Vec<CatalogEntry> {
        match model {
            "Lexmark MS621" => vec![CatalogEntry {
                part_number: "56F1H00".to_string(),
                description: "Lexmark High Yield Return Program Toner".to_string(),
                consumable: ConsumableKind::TonerBlack,
                unit_price_cents: 22_999,
            }],
            "Lexmark CS521" => vec![
                CatalogEntry {
                    part_number: "78C1UK0".to_string(),
                    description: "Lexmark Ultra High Yield Black Toner".to_string(),
                    consumable: ConsumableKind::TonerBlack,
                    unit_price_cents: 19_499,
                },
                CatalogEntry {
                    part_number: "78C1UC0".to_string(),
                    description: "Lexmark Ultra High Yield Cyan Toner".to_string(),
                    consumable: ConsumableKind::TonerCyan,
                    unit_price_cents: 25_999,
                },
                CatalogEntry {
                    part_number: "78C1UM0".to_string(),
                    description: "Lexmark Ultra High Yield Magenta Toner".to_string(),
                    consumable: ConsumableKind::TonerMagenta,
                    unit_price_cents: 25_999,
                },
                CatalogEntry {
                    part_number: "78C1UY0".to_string(),
                    description: "Lexmark Ultra High Yield Yellow Toner".to_string(),
                    consumable: ConsumableKind::TonerYellow,
                    unit_price_cents: 25_999,
                },
            ],
            _ => Vec::new(),
        }
    }
}

impl SupplyVendor for LexmarkSupplyClient {
    async fn submit_order(
        &self,
        request: &ReorderRequest,
        line_items: &[OrderLineItem],
    ) -> Result<VendorOrder, SupplyError> {
        info!(
            vendor = "Lexmark",
            reorder_id = %request.id,
            item_count = line_items.len(),
            base_url = %self.config.base_url,
            "stubbed Lexmark Cartridge Collection API order submission"
        );

        let vendor_order_id = format!("LXK-{}", Uuid::now_v7());

        Ok(VendorOrder {
            reorder_id: request.id,
            vendor_order_id,
            vendor_name: self.vendor_name().to_string(),
            estimated_delivery_days: Some(6),
        })
    }

    async fn check_order_status(
        &self,
        vendor_order_id: &str,
    ) -> Result<VendorOrderStatus, SupplyError> {
        info!(
            vendor = "Lexmark",
            vendor_order_id = vendor_order_id,
            "stubbed Lexmark order status check"
        );

        Ok(VendorOrderStatus::Accepted)
    }

    async fn cancel_order(&self, vendor_order_id: &str) -> Result<(), SupplyError> {
        info!(
            vendor = "Lexmark",
            vendor_order_id = vendor_order_id,
            "stubbed Lexmark order cancellation"
        );

        Ok(())
    }

    fn vendor_name(&self) -> &'static str {
        "Lexmark"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorder::{ReorderStatus, ReorderTrigger};

    fn test_config() -> LexmarkConfig {
        LexmarkConfig {
            base_url: "https://api.lexmark.example.com/cartridge/v1".to_string(),
            api_key: SecretString::from("lexmark-test-api-key-abcde".to_string()),
            dealer_code: "LXK-DEALER-001".to_string(),
        }
    }

    fn test_reorder_request() -> ReorderRequest {
        ReorderRequest {
            id: Uuid::now_v7(),
            printer_id: pf_common::fleet::PrinterId::new("PRN-0003").unwrap(),
            consumable: ConsumableKind::TonerBlack,
            trigger: ReorderTrigger::Predictive,
            current_level_pct: 12,
            estimated_cost_cents: Some(22_999),
            status: ReorderStatus::Approved,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn lexmark_config_debug_redacts_api_key() {
        let cfg = test_config();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("lexmark-test-api-key-abcde"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn lexmark_config_serde_roundtrip() {
        let json = serde_json::json!({
            "base_url": "https://api.lexmark.example.com/cartridge/v1",
            "api_key": "lexmark-key",
            "dealer_code": "LXK-DEALER-001"
        });
        let cfg: LexmarkConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.base_url, "https://api.lexmark.example.com/cartridge/v1");
        assert_eq!(cfg.dealer_code, "LXK-DEALER-001");
    }

    #[tokio::test]
    async fn lexmark_submit_order_produces_valid_vendor_order() {
        let client = LexmarkSupplyClient::new(test_config());
        let request = test_reorder_request();
        let items = vec![OrderLineItem {
            consumable: ConsumableKind::TonerBlack,
            quantity: 1,
            part_number: Some("56F1H00".to_string()),
        }];

        let order = client.submit_order(&request, &items).await.unwrap();
        assert_eq!(order.vendor_name, "Lexmark");
        assert_eq!(order.reorder_id, request.id);
        assert!(order.vendor_order_id.starts_with("LXK-"));
        assert_eq!(order.estimated_delivery_days, Some(6));
    }

    #[tokio::test]
    async fn lexmark_check_order_status_returns_accepted() {
        let client = LexmarkSupplyClient::new(test_config());
        let status = client.check_order_status("LXK-TEST-001").await.unwrap();
        assert_eq!(status, VendorOrderStatus::Accepted);
    }

    #[tokio::test]
    async fn lexmark_cancel_order_succeeds() {
        let client = LexmarkSupplyClient::new(test_config());
        let result = client.cancel_order("LXK-TEST-001").await;
        assert!(result.is_ok());
    }

    #[test]
    fn lexmark_catalog_returns_entries_for_known_model() {
        let catalog = LexmarkSupplyClient::get_catalog("Lexmark CS521");
        assert_eq!(catalog.len(), 4);
        assert!(catalog.iter().any(|e| e.part_number == "78C1UK0"));
    }

    #[test]
    fn lexmark_catalog_returns_empty_for_unknown_model() {
        let catalog = LexmarkSupplyClient::get_catalog("Unknown Printer 9000");
        assert!(catalog.is_empty());
    }

    #[test]
    fn lexmark_part_number_mapping_for_known_model() {
        let part = LexmarkSupplyClient::map_part_number(
            "Lexmark CS521",
            &ConsumableKind::TonerMagenta,
        );
        assert_eq!(part, Some("78C1UM0"));
    }

    #[test]
    fn lexmark_part_number_mapping_returns_none_for_unknown() {
        let part = LexmarkSupplyClient::map_part_number(
            "Unknown Printer",
            &ConsumableKind::TonerBlack,
        );
        assert!(part.is_none());
    }

    #[test]
    fn lexmark_vendor_name() {
        let client = LexmarkSupplyClient::new(test_config());
        assert_eq!(client.vendor_name(), "Lexmark");
    }
}
