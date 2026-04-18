// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Konica Minolta Optimized Print Services (OPS) API client.
//!
//! Implements the [`SupplyVendor`] trait for ordering consumables through
//! the Konica Minolta OPS API. HTTP calls are currently stubbed — the
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

/// A catalog entry representing an available Konica Minolta supply.
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

/// Configuration for the Konica Minolta OPS API client.
///
/// **Security:** The `api_key` field uses [`SecretString`] and is redacted
/// in `Debug` output. NIST 800-53 Rev 5: SC-12.
#[derive(Clone, Deserialize)]
pub struct KonicaMinoltaConfig {
    /// Base URL of the Konica Minolta OPS API.
    pub base_url: String,
    /// API key for authentication.
    pub api_key: SecretString,
    /// Konica Minolta service agreement number.
    pub agreement_id: String,
}

impl std::fmt::Debug for KonicaMinoltaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KonicaMinoltaConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("agreement_id", &self.agreement_id)
            .finish()
    }
}

/// Konica Minolta OPS API client.
pub struct KonicaMinoltaSupplyClient {
    config: KonicaMinoltaConfig,
}

impl KonicaMinoltaSupplyClient {
    /// Create a new Konica Minolta OPS API client.
    #[must_use]
    pub fn new(config: KonicaMinoltaConfig) -> Self {
        Self { config }
    }

    /// Return the vendor-specific part number for a given consumable and
    /// printer model, if known.
    #[must_use]
    pub fn map_part_number(model: &str, consumable: &ConsumableKind) -> Option<&'static str> {
        match (model, consumable) {
            ("bizhub C258", ConsumableKind::TonerBlack) => Some("TN324K"),
            ("bizhub C258", ConsumableKind::TonerCyan) => Some("TN324C"),
            ("bizhub C258", ConsumableKind::TonerMagenta) => Some("TN324M"),
            ("bizhub C258", ConsumableKind::TonerYellow) => Some("TN324Y"),
            ("bizhub 458e", ConsumableKind::TonerBlack) => Some("TN516"),
            ("bizhub C360i", ConsumableKind::TonerBlack) => Some("TN328K"),
            ("bizhub C360i", ConsumableKind::TonerCyan) => Some("TN328C"),
            ("bizhub C360i", ConsumableKind::TonerMagenta) => Some("TN328M"),
            ("bizhub C360i", ConsumableKind::TonerYellow) => Some("TN328Y"),
            _ => None,
        }
    }

    /// Return the catalog of available supplies for a printer model.
    ///
    /// This is a stub that returns sample data for known Konica Minolta models.
    #[must_use]
    pub fn get_catalog(model: &str) -> Vec<CatalogEntry> {
        match model {
            "bizhub C258" => vec![
                CatalogEntry {
                    part_number: "TN324K".to_string(),
                    description: "Konica Minolta TN324K Black Toner".to_string(),
                    consumable: ConsumableKind::TonerBlack,
                    unit_price_cents: 8_999,
                },
                CatalogEntry {
                    part_number: "TN324C".to_string(),
                    description: "Konica Minolta TN324C Cyan Toner".to_string(),
                    consumable: ConsumableKind::TonerCyan,
                    unit_price_cents: 14_999,
                },
                CatalogEntry {
                    part_number: "TN324M".to_string(),
                    description: "Konica Minolta TN324M Magenta Toner".to_string(),
                    consumable: ConsumableKind::TonerMagenta,
                    unit_price_cents: 14_999,
                },
                CatalogEntry {
                    part_number: "TN324Y".to_string(),
                    description: "Konica Minolta TN324Y Yellow Toner".to_string(),
                    consumable: ConsumableKind::TonerYellow,
                    unit_price_cents: 14_999,
                },
            ],
            "bizhub 458e" => vec![CatalogEntry {
                part_number: "TN516".to_string(),
                description: "Konica Minolta TN516 Black Toner".to_string(),
                consumable: ConsumableKind::TonerBlack,
                unit_price_cents: 11_499,
            }],
            _ => Vec::new(),
        }
    }
}

impl SupplyVendor for KonicaMinoltaSupplyClient {
    async fn submit_order(
        &self,
        request: &ReorderRequest,
        line_items: &[OrderLineItem],
    ) -> Result<VendorOrder, SupplyError> {
        info!(
            vendor = "Konica Minolta",
            reorder_id = %request.id,
            item_count = line_items.len(),
            base_url = %self.config.base_url,
            "stubbed Konica Minolta OPS API order submission"
        );

        let vendor_order_id = format!("KM-{}", Uuid::now_v7());

        Ok(VendorOrder {
            reorder_id: request.id,
            vendor_order_id,
            vendor_name: self.vendor_name().to_string(),
            estimated_delivery_days: Some(8),
        })
    }

    async fn check_order_status(
        &self,
        vendor_order_id: &str,
    ) -> Result<VendorOrderStatus, SupplyError> {
        info!(
            vendor = "Konica Minolta",
            vendor_order_id = vendor_order_id,
            "stubbed Konica Minolta order status check"
        );

        Ok(VendorOrderStatus::Accepted)
    }

    async fn cancel_order(&self, vendor_order_id: &str) -> Result<(), SupplyError> {
        info!(
            vendor = "Konica Minolta",
            vendor_order_id = vendor_order_id,
            "stubbed Konica Minolta order cancellation"
        );

        Ok(())
    }

    fn vendor_name(&self) -> &'static str {
        "Konica Minolta"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorder::{ReorderStatus, ReorderTrigger};

    fn test_config() -> KonicaMinoltaConfig {
        KonicaMinoltaConfig {
            base_url: "https://api.konicaminolta.example.com/ops/v1".to_string(),
            api_key: SecretString::from("km-test-api-key-xyz99".to_string()),
            agreement_id: "KM-AGREE-001".to_string(),
        }
    }

    fn test_reorder_request() -> ReorderRequest {
        ReorderRequest {
            id: Uuid::now_v7(),
            printer_id: pf_common::fleet::PrinterId::new("PRN-0004").unwrap(),
            consumable: ConsumableKind::TonerBlack,
            trigger: ReorderTrigger::Threshold,
            current_level_pct: 5,
            estimated_cost_cents: Some(8_999),
            status: ReorderStatus::Approved,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn km_config_debug_redacts_api_key() {
        let cfg = test_config();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("km-test-api-key-xyz99"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn km_config_serde_roundtrip() {
        let json = serde_json::json!({
            "base_url": "https://api.konicaminolta.example.com/ops/v1",
            "api_key": "km-key",
            "agreement_id": "KM-AGREE-001"
        });
        let cfg: KonicaMinoltaConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            cfg.base_url,
            "https://api.konicaminolta.example.com/ops/v1"
        );
        assert_eq!(cfg.agreement_id, "KM-AGREE-001");
    }

    #[tokio::test]
    async fn km_submit_order_produces_valid_vendor_order() {
        let client = KonicaMinoltaSupplyClient::new(test_config());
        let request = test_reorder_request();
        let items = vec![OrderLineItem {
            consumable: ConsumableKind::TonerBlack,
            quantity: 1,
            part_number: Some("TN324K".to_string()),
        }];

        let order = client.submit_order(&request, &items).await.unwrap();
        assert_eq!(order.vendor_name, "Konica Minolta");
        assert_eq!(order.reorder_id, request.id);
        assert!(order.vendor_order_id.starts_with("KM-"));
        assert_eq!(order.estimated_delivery_days, Some(8));
    }

    #[tokio::test]
    async fn km_check_order_status_returns_accepted() {
        let client = KonicaMinoltaSupplyClient::new(test_config());
        let status = client.check_order_status("KM-TEST-001").await.unwrap();
        assert_eq!(status, VendorOrderStatus::Accepted);
    }

    #[tokio::test]
    async fn km_cancel_order_succeeds() {
        let client = KonicaMinoltaSupplyClient::new(test_config());
        let result = client.cancel_order("KM-TEST-001").await;
        assert!(result.is_ok());
    }

    #[test]
    fn km_catalog_returns_entries_for_known_model() {
        let catalog = KonicaMinoltaSupplyClient::get_catalog("bizhub C258");
        assert_eq!(catalog.len(), 4);
        assert!(catalog.iter().any(|e| e.part_number == "TN324K"));
    }

    #[test]
    fn km_catalog_returns_empty_for_unknown_model() {
        let catalog = KonicaMinoltaSupplyClient::get_catalog("Unknown Printer 9000");
        assert!(catalog.is_empty());
    }

    #[test]
    fn km_part_number_mapping_for_known_model() {
        let part = KonicaMinoltaSupplyClient::map_part_number(
            "bizhub C258",
            &ConsumableKind::TonerYellow,
        );
        assert_eq!(part, Some("TN324Y"));
    }

    #[test]
    fn km_part_number_mapping_returns_none_for_unknown() {
        let part = KonicaMinoltaSupplyClient::map_part_number(
            "Unknown Printer",
            &ConsumableKind::TonerBlack,
        );
        assert!(part.is_none());
    }

    #[test]
    fn km_vendor_name() {
        let client = KonicaMinoltaSupplyClient::new(test_config());
        assert_eq!(client.vendor_name(), "Konica Minolta");
    }
}
