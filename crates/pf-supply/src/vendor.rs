// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SupplyVendor` trait for vendor API integration.
//!
//! All vendor integrations (HP, Xerox, Lexmark, Konica Minolta)
//! implement this trait. Adding a new vendor means writing a single
//! new implementation.
//!
//! **Security:** Vendor API keys are stored as [`secrecy::SecretString`]
//! and MUST never appear in logs, error messages, or serialized output.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SupplyError;
use crate::monitoring::ConsumableKind;
use crate::reorder::ReorderRequest;

/// Details of an order submitted to a vendor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorOrder {
    /// `PrintForge` internal reorder ID.
    pub reorder_id: Uuid,
    /// Vendor-assigned order/confirmation number.
    pub vendor_order_id: String,
    /// Vendor name.
    pub vendor_name: String,
    /// Estimated delivery in calendar days (vendor-provided).
    pub estimated_delivery_days: Option<u32>,
}

/// Details for ordering a specific consumable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderLineItem {
    /// Which consumable to order.
    pub consumable: ConsumableKind,
    /// Quantity to order.
    pub quantity: u32,
    /// Vendor part number, if known.
    pub part_number: Option<String>,
}

/// Trait for vendor supply ordering APIs.
///
/// Implementations are expected to handle authentication using their
/// configured [`secrecy::SecretString`] API key internally.
///
/// # Errors
///
/// All methods return [`SupplyError::VendorApi`] on communication or
/// business-logic failures from the vendor side.
pub trait SupplyVendor: Send + Sync {
    /// Submit a supply order to the vendor.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::VendorApi`] if the vendor API rejects the
    /// order or is unreachable.
    fn submit_order(
        &self,
        request: &ReorderRequest,
        line_items: &[OrderLineItem],
    ) -> impl std::future::Future<Output = Result<VendorOrder, SupplyError>> + Send;

    /// Check the status of a previously submitted order.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::VendorApi`] if the vendor API is
    /// unreachable or the order ID is unknown.
    fn check_order_status(
        &self,
        vendor_order_id: &str,
    ) -> impl std::future::Future<Output = Result<VendorOrderStatus, SupplyError>> + Send;

    /// Cancel a previously submitted order, if the vendor supports it.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::VendorApi`] if cancellation fails or is
    /// not supported.
    fn cancel_order(
        &self,
        vendor_order_id: &str,
    ) -> impl std::future::Future<Output = Result<(), SupplyError>> + Send;

    /// Return the human-readable vendor name.
    fn vendor_name(&self) -> &str;
}

/// Status of a vendor order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VendorOrderStatus {
    /// Order accepted, not yet shipped.
    Accepted,
    /// Order has shipped.
    Shipped {
        /// Tracking number, if provided.
        tracking_number: Option<String>,
    },
    /// Order delivered.
    Delivered,
    /// Order cancelled.
    Cancelled,
    /// Vendor returned an unknown status.
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test double implementing `SupplyVendor` for unit tests.
    struct MockVendor;

    impl SupplyVendor for MockVendor {
        async fn submit_order(
            &self,
            request: &ReorderRequest,
            _line_items: &[OrderLineItem],
        ) -> Result<VendorOrder, SupplyError> {
            Ok(VendorOrder {
                reorder_id: request.id,
                vendor_order_id: "MOCK-ORD-001".to_string(),
                vendor_name: "MockVendor".to_string(),
                estimated_delivery_days: Some(3),
            })
        }

        async fn check_order_status(
            &self,
            _vendor_order_id: &str,
        ) -> Result<VendorOrderStatus, SupplyError> {
            Ok(VendorOrderStatus::Accepted)
        }

        async fn cancel_order(&self, _vendor_order_id: &str) -> Result<(), SupplyError> {
            Ok(())
        }

        fn vendor_name(&self) -> &'static str {
            "MockVendor"
        }
    }

    #[tokio::test]
    async fn mock_vendor_submit_order() {
        let vendor = MockVendor;
        let request = ReorderRequest {
            id: Uuid::now_v7(),
            printer_id: pf_common::fleet::PrinterId::new("PRN-0001").unwrap(),
            consumable: ConsumableKind::TonerBlack,
            trigger: crate::reorder::ReorderTrigger::Threshold,
            current_level_pct: 10,
            estimated_cost_cents: Some(5_000),
            status: crate::reorder::ReorderStatus::Approved,
            created_at: chrono::Utc::now(),
        };
        let items = vec![OrderLineItem {
            consumable: ConsumableKind::TonerBlack,
            quantity: 1,
            part_number: Some("HP-CF410X".to_string()),
        }];

        let result = vendor.submit_order(&request, &items).await;
        assert!(result.is_ok());
        let order = result.unwrap();
        assert_eq!(order.vendor_name, "MockVendor");
        assert_eq!(order.vendor_order_id, "MOCK-ORD-001");
    }

    #[tokio::test]
    async fn mock_vendor_check_status() {
        let vendor = MockVendor;
        let status = vendor.check_order_status("MOCK-ORD-001").await.unwrap();
        assert_eq!(status, VendorOrderStatus::Accepted);
    }
}
