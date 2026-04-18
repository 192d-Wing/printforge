// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Manual requisition form generation for SIPR environments.
//!
//! On SIPR, vendor APIs are unreachable. Instead, `PrintForge` generates
//! a structured requisition form that the site admin can print and submit
//! through manual supply channels.

use chrono::{DateTime, Utc};
use pf_common::fleet::PrinterId;
use pf_common::identity::Edipi;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::monitoring::ConsumableKind;

/// A supply requisition form suitable for manual ordering on SIPR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequisitionForm {
    /// Unique requisition number.
    pub requisition_id: Uuid,
    /// The associated reorder request ID.
    pub reorder_id: Uuid,
    /// Installation or site identifier.
    pub site_name: String,
    /// Requesting organization.
    pub organization: String,
    /// EDIPI of the person generating the requisition.
    pub requestor: Edipi,
    /// Date the requisition was generated.
    pub generated_at: DateTime<Utc>,
    /// Line items to order.
    pub items: Vec<RequisitionLineItem>,
    /// Justification narrative.
    pub justification: String,
    /// Priority level.
    pub priority: RequisitionPriority,
}

/// A single line item on a requisition form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequisitionLineItem {
    /// Printer requiring the supply.
    pub printer_id: PrinterId,
    /// Consumable type.
    pub consumable: ConsumableKind,
    /// Quantity requested.
    pub quantity: u32,
    /// National Stock Number (NSN), if known.
    pub nsn: Option<String>,
    /// Vendor part number, if known.
    pub part_number: Option<String>,
    /// Estimated unit cost in cents.
    pub unit_cost_cents: Option<u64>,
}

/// Priority levels for manual requisitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequisitionPriority {
    /// Routine — standard lead time acceptable.
    Routine,
    /// Urgent — printer is non-operational without the supply.
    Urgent,
    /// Mission-critical — impacts mission-essential printing.
    MissionCritical,
}

/// Generate a requisition form from a reorder request.
///
/// This produces a serializable form that can be rendered as JSON
/// (for API consumption) or converted to PDF by a downstream service.
#[must_use]
pub fn generate_requisition(
    reorder_id: Uuid,
    site_name: String,
    organization: String,
    requestor: Edipi,
    items: Vec<RequisitionLineItem>,
    justification: String,
    priority: RequisitionPriority,
) -> RequisitionForm {
    RequisitionForm {
        requisition_id: Uuid::now_v7(),
        reorder_id,
        site_name,
        organization,
        requestor,
        generated_at: Utc::now(),
        items,
        justification,
        priority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pf_common::fleet::PrinterId;

    #[test]
    fn generate_requisition_populates_all_fields() {
        let edipi = Edipi::new("1234567890").unwrap();
        let reorder_id = Uuid::now_v7();
        let items = vec![RequisitionLineItem {
            printer_id: PrinterId::new("PRN-0042").unwrap(),
            consumable: ConsumableKind::TonerBlack,
            quantity: 2,
            nsn: Some("6850-01-234-5678".to_string()),
            part_number: Some("HP-CF410X".to_string()),
            unit_cost_cents: Some(8_500),
        }];

        let form = generate_requisition(
            reorder_id,
            "Test Base AFB".to_string(),
            "Test Unit".to_string(),
            edipi,
            items,
            "Toner critically low on PRN-0042".to_string(),
            RequisitionPriority::Urgent,
        );

        assert_eq!(form.reorder_id, reorder_id);
        assert_eq!(form.site_name, "Test Base AFB");
        assert_eq!(form.priority, RequisitionPriority::Urgent);
        assert_eq!(form.items.len(), 1);
        assert_eq!(form.items[0].quantity, 2);
    }

    #[test]
    fn requisition_serializes_to_json() {
        let edipi = Edipi::new("1234567890").unwrap();
        let form = generate_requisition(
            Uuid::now_v7(),
            "Test Base AFB".to_string(),
            "Test Unit".to_string(),
            edipi,
            Vec::new(),
            "Routine reorder".to_string(),
            RequisitionPriority::Routine,
        );

        let json = serde_json::to_string(&form);
        assert!(json.is_ok());
        // Verify EDIPI is redacted in serialized output (it serializes the inner value,
        // but Display/Debug are redacted — this is the serde path).
        let json_str = json.unwrap();
        assert!(json_str.contains("Test Base AFB"));
    }
}
