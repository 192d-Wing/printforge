// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Xerox Supplies Assistant API client.
//!
//! Implements the [`SupplyVendor`] trait for ordering consumables through
//! the Xerox Supplies Assistant API. HTTP calls are currently stubbed —
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

/// A catalog entry representing an available Xerox supply.
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

/// Configuration for the Xerox Supplies Assistant API client.
///
/// **Security:** The `api_key` field uses [`SecretString`] and is redacted
/// in `Debug` output. NIST 800-53 Rev 5: SC-12.
#[derive(Clone, Deserialize)]
pub struct XeroxConfig {
    /// Base URL of the Xerox Supplies Assistant API.
    pub base_url: String,
    /// API key for authentication.
    pub api_key: SecretString,
    /// Xerox contract number.
    pub contract_id: String,
}

impl std::fmt::Debug for XeroxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XeroxConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("contract_id", &self.contract_id)
            .finish()
    }
}

/// Xerox Supplies Assistant API client.
pub struct XeroxSupplyClient {
    config: XeroxConfig,
}

impl XeroxSupplyClient {
    /// Create a new Xerox Supplies Assistant API client.
    #[must_use]
    pub fn new(config: XeroxConfig) -> Self {
        Self { config }
    }

    /// Return the vendor-specific part number for a given consumable and
    /// printer model, if known.
    #[must_use]
    pub fn map_part_number(model: &str, consumable: &ConsumableKind) -> Option<&'static str> {
        match (model, consumable) {
            ("Xerox VersaLink C405", ConsumableKind::TonerBlack) => Some("106R03524"),
            ("Xerox VersaLink C405", ConsumableKind::TonerCyan) => Some("106R03526"),
            ("Xerox VersaLink C405", ConsumableKind::TonerMagenta) => Some("106R03527"),
            ("Xerox VersaLink C405", ConsumableKind::TonerYellow) => Some("106R03525"),
            ("Xerox AltaLink C8055", ConsumableKind::TonerBlack) => Some("006R01697"),
            ("Xerox AltaLink C8055", ConsumableKind::TonerCyan) => Some("006R01698"),
            ("Xerox AltaLink C8055", ConsumableKind::TonerMagenta) => Some("006R01699"),
            ("Xerox AltaLink C8055", ConsumableKind::TonerYellow) => Some("006R01700"),
            ("Xerox B410", ConsumableKind::TonerBlack) => Some("006R04726"),
            _ => None,
        }
    }

    /// Return the catalog of available supplies for a printer model.
    ///
    /// This is a stub that returns sample data for known Xerox printer models.
    #[must_use]
    pub fn get_catalog(model: &str) -> Vec<CatalogEntry> {
        match model {
            "Xerox VersaLink C405" => vec![
                CatalogEntry {
                    part_number: "106R03524".to_string(),
                    description: "Xerox Extra High Capacity Black Toner".to_string(),
                    consumable: ConsumableKind::TonerBlack,
                    unit_price_cents: 16_499,
                },
                CatalogEntry {
                    part_number: "106R03526".to_string(),
                    description: "Xerox Extra High Capacity Cyan Toner".to_string(),
                    consumable: ConsumableKind::TonerCyan,
                    unit_price_cents: 24_999,
                },
                CatalogEntry {
                    part_number: "106R03527".to_string(),
                    description: "Xerox Extra High Capacity Magenta Toner".to_string(),
                    consumable: ConsumableKind::TonerMagenta,
                    unit_price_cents: 24_999,
                },
                CatalogEntry {
                    part_number: "106R03525".to_string(),
                    description: "Xerox Extra High Capacity Yellow Toner".to_string(),
                    consumable: ConsumableKind::TonerYellow,
                    unit_price_cents: 24_999,
                },
            ],
            "Xerox B410" => vec![CatalogEntry {
                part_number: "006R04726".to_string(),
                description: "Xerox B410 High Capacity Black Toner".to_string(),
                consumable: ConsumableKind::TonerBlack,
                unit_price_cents: 12_999,
            }],
            _ => Vec::new(),
        }
    }
}

impl SupplyVendor for XeroxSupplyClient {
    async fn submit_order(
        &self,
        request: &ReorderRequest,
        line_items: &[OrderLineItem],
    ) -> Result<VendorOrder, SupplyError> {
        info!(
            vendor = "Xerox",
            reorder_id = %request.id,
            item_count = line_items.len(),
            base_url = %self.config.base_url,
            "stubbed Xerox Supplies Assistant API order submission"
        );

        let vendor_order_id = format!("XRX-{}", Uuid::now_v7());

        Ok(VendorOrder {
            reorder_id: request.id,
            vendor_order_id,
            vendor_name: self.vendor_name().to_string(),
            estimated_delivery_days: Some(7),
        })
    }

    async fn check_order_status(
        &self,
        vendor_order_id: &str,
    ) -> Result<VendorOrderStatus, SupplyError> {
        info!(
            vendor = "Xerox",
            vendor_order_id = vendor_order_id,
            "stubbed Xerox order status check"
        );

        Ok(VendorOrderStatus::Accepted)
    }

    async fn cancel_order(&self, vendor_order_id: &str) -> Result<(), SupplyError> {
        info!(
            vendor = "Xerox",
            vendor_order_id = vendor_order_id,
            "stubbed Xerox order cancellation"
        );

        Ok(())
    }

    fn vendor_name(&self) -> &'static str {
        "Xerox"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorder::{ReorderStatus, ReorderTrigger};

    fn test_config() -> XeroxConfig {
        XeroxConfig {
            base_url: "https://api.xerox.example.com/supplies/v2".to_string(),
            api_key: SecretString::from("xerox-test-api-key-67890".to_string()),
            contract_id: "XRX-CONTRACT-001".to_string(),
        }
    }

    fn test_reorder_request() -> ReorderRequest {
        ReorderRequest {
            id: Uuid::now_v7(),
            printer_id: pf_common::fleet::PrinterId::new("PRN-0002").unwrap(),
            consumable: ConsumableKind::TonerBlack,
            trigger: ReorderTrigger::Threshold,
            current_level_pct: 8,
            estimated_cost_cents: Some(16_499),
            status: ReorderStatus::Approved,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn xerox_config_debug_redacts_api_key() {
        let cfg = test_config();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("xerox-test-api-key-67890"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn xerox_config_serde_roundtrip() {
        let json = serde_json::json!({
            "base_url": "https://api.xerox.example.com/supplies/v2",
            "api_key": "xerox-key",
            "contract_id": "XRX-CONTRACT-001"
        });
        let cfg: XeroxConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.base_url, "https://api.xerox.example.com/supplies/v2");
        assert_eq!(cfg.contract_id, "XRX-CONTRACT-001");
    }

    #[tokio::test]
    async fn xerox_submit_order_produces_valid_vendor_order() {
        let client = XeroxSupplyClient::new(test_config());
        let request = test_reorder_request();
        let items = vec![OrderLineItem {
            consumable: ConsumableKind::TonerBlack,
            quantity: 2,
            part_number: Some("106R03524".to_string()),
        }];

        let order = client.submit_order(&request, &items).await.unwrap();
        assert_eq!(order.vendor_name, "Xerox");
        assert_eq!(order.reorder_id, request.id);
        assert!(order.vendor_order_id.starts_with("XRX-"));
        assert_eq!(order.estimated_delivery_days, Some(7));
    }

    #[tokio::test]
    async fn xerox_check_order_status_returns_accepted() {
        let client = XeroxSupplyClient::new(test_config());
        let status = client.check_order_status("XRX-TEST-001").await.unwrap();
        assert_eq!(status, VendorOrderStatus::Accepted);
    }

    #[tokio::test]
    async fn xerox_cancel_order_succeeds() {
        let client = XeroxSupplyClient::new(test_config());
        let result = client.cancel_order("XRX-TEST-001").await;
        assert!(result.is_ok());
    }

    #[test]
    fn xerox_catalog_returns_entries_for_known_model() {
        let catalog = XeroxSupplyClient::get_catalog("Xerox VersaLink C405");
        assert_eq!(catalog.len(), 4);
        assert!(catalog.iter().any(|e| e.part_number == "106R03524"));
    }

    #[test]
    fn xerox_catalog_returns_empty_for_unknown_model() {
        let catalog = XeroxSupplyClient::get_catalog("Unknown Printer 9000");
        assert!(catalog.is_empty());
    }

    #[test]
    fn xerox_part_number_mapping_for_known_model() {
        let part = XeroxSupplyClient::map_part_number(
            "Xerox VersaLink C405",
            &ConsumableKind::TonerCyan,
        );
        assert_eq!(part, Some("106R03526"));
    }

    #[test]
    fn xerox_part_number_mapping_returns_none_for_unknown() {
        let part = XeroxSupplyClient::map_part_number(
            "Unknown Printer",
            &ConsumableKind::TonerBlack,
        );
        assert!(part.is_none());
    }

    #[test]
    fn xerox_vendor_name() {
        let client = XeroxSupplyClient::new(test_config());
        assert_eq!(client.vendor_name(), "Xerox");
    }
}
