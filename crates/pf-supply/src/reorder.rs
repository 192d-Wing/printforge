// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Reorder trigger logic: threshold-based and prediction-based.
//!
//! A reorder fires on **whichever trigger fires first**:
//! 1. Static threshold — consumable level <= configured percentage.
//! 2. Predictive trigger — estimated days-until-empty < lead time + buffer.

use chrono::{DateTime, Utc};
use pf_common::fleet::PrinterId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{LeadTimeConfig, SupplyConfig};
use crate::monitoring::{ConsumableKind, ThresholdAlert};
use crate::prediction::DepletionEstimate;

/// Reason a reorder was triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReorderTrigger {
    /// The consumable level dropped to or below the static threshold.
    Threshold,
    /// The predicted days-until-empty fell below the lead time window.
    Predictive,
}

/// Status of a reorder through its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReorderStatus {
    /// Waiting for approval.
    PendingApproval,
    /// Approved (auto or manual).
    Approved,
    /// Submitted to vendor or requisition generated.
    Submitted,
    /// Vendor confirmed fulfillment.
    Fulfilled,
    /// Cancelled before submission.
    Cancelled,
}

/// A supply reorder request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderRequest {
    /// Unique identifier for this reorder.
    pub id: Uuid,
    /// Printer that needs supplies.
    pub printer_id: PrinterId,
    /// Which consumable needs reordering.
    pub consumable: ConsumableKind,
    /// What triggered the reorder.
    pub trigger: ReorderTrigger,
    /// Current supply level at the time of trigger.
    pub current_level_pct: u8,
    /// Estimated cost in cents (if known).
    pub estimated_cost_cents: Option<u64>,
    /// Current lifecycle status.
    pub status: ReorderStatus,
    /// When the reorder was created.
    pub created_at: DateTime<Utc>,
}

/// Evaluate whether a threshold alert should produce a reorder.
///
/// Returns `Some(ReorderRequest)` if the alert warrants a new order.
#[must_use]
pub fn evaluate_threshold_trigger(alert: &ThresholdAlert) -> ReorderRequest {
    ReorderRequest {
        id: Uuid::now_v7(),
        printer_id: alert.printer_id.clone(),
        consumable: alert.consumable.clone(),
        trigger: ReorderTrigger::Threshold,
        current_level_pct: alert.current_pct,
        estimated_cost_cents: None,
        status: ReorderStatus::PendingApproval,
        created_at: Utc::now(),
    }
}

/// Evaluate whether a depletion estimate should produce a predictive reorder.
///
/// Returns `Some(ReorderRequest)` if the estimated days until empty is
/// less than or equal to `lead_time_days + buffer_days`.
#[must_use]
pub fn evaluate_predictive_trigger(
    printer_id: &PrinterId,
    estimate: &DepletionEstimate,
    lead_time: &LeadTimeConfig,
    vendor_lead_time_override: Option<u32>,
) -> Option<ReorderRequest> {
    let days_until_empty = estimate.days_until_empty?;

    let effective_lead = vendor_lead_time_override.unwrap_or(lead_time.default_days);
    let trigger_horizon = f64::from(effective_lead + lead_time.buffer_days);

    if days_until_empty <= trigger_horizon {
        Some(ReorderRequest {
            id: Uuid::now_v7(),
            printer_id: printer_id.clone(),
            consumable: estimate.consumable.clone(),
            trigger: ReorderTrigger::Predictive,
            current_level_pct: estimate.current_level_pct,
            estimated_cost_cents: None,
            status: ReorderStatus::PendingApproval,
            created_at: Utc::now(),
        })
    } else {
        None
    }
}

/// Convenience: evaluate both threshold and predictive triggers, returning
/// the first that fires (threshold takes priority if both fire simultaneously).
#[must_use]
pub fn evaluate_triggers(
    alert: Option<&ThresholdAlert>,
    estimate: Option<&DepletionEstimate>,
    printer_id: &PrinterId,
    config: &SupplyConfig,
) -> Option<ReorderRequest> {
    // Threshold trigger takes priority.
    if let Some(a) = alert {
        return Some(evaluate_threshold_trigger(a));
    }

    if let Some(est) = estimate {
        return evaluate_predictive_trigger(printer_id, est, &config.lead_time, None);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::ConsumableKind;
    use pf_common::fleet::PrinterId;

    fn test_printer() -> PrinterId {
        PrinterId::new("PRN-0042").unwrap()
    }

    #[test]
    fn threshold_trigger_creates_pending_order() {
        let alert = ThresholdAlert {
            printer_id: test_printer(),
            consumable: ConsumableKind::TonerBlack,
            current_pct: 10,
            threshold_pct: 15,
        };
        let order = evaluate_threshold_trigger(&alert);
        assert_eq!(order.trigger, ReorderTrigger::Threshold);
        assert_eq!(order.status, ReorderStatus::PendingApproval);
        assert_eq!(order.current_level_pct, 10);
    }

    #[test]
    fn predictive_trigger_fires_when_within_lead_time() {
        let estimate = DepletionEstimate {
            consumable: ConsumableKind::TonerBlack,
            avg_daily_consumption: 1.0,
            days_until_empty: Some(8.0), // 8 days < 7 + 3 = 10
            current_level_pct: 8,
        };
        let lead = LeadTimeConfig::default();
        let order = evaluate_predictive_trigger(&test_printer(), &estimate, &lead, None);
        assert!(order.is_some());
        assert_eq!(order.unwrap().trigger, ReorderTrigger::Predictive);
    }

    #[test]
    fn predictive_trigger_does_not_fire_when_plenty_of_time() {
        let estimate = DepletionEstimate {
            consumable: ConsumableKind::TonerBlack,
            avg_daily_consumption: 0.5,
            days_until_empty: Some(60.0),
            current_level_pct: 30,
        };
        let lead = LeadTimeConfig::default();
        let order = evaluate_predictive_trigger(&test_printer(), &estimate, &lead, None);
        assert!(order.is_none());
    }

    #[test]
    fn predictive_trigger_does_not_fire_when_no_depletion() {
        let estimate = DepletionEstimate {
            consumable: ConsumableKind::TonerBlack,
            avg_daily_consumption: 0.0,
            days_until_empty: None,
            current_level_pct: 80,
        };
        let lead = LeadTimeConfig::default();
        let order = evaluate_predictive_trigger(&test_printer(), &estimate, &lead, None);
        assert!(order.is_none());
    }

    #[test]
    fn threshold_takes_priority_over_prediction() {
        let alert = ThresholdAlert {
            printer_id: test_printer(),
            consumable: ConsumableKind::TonerBlack,
            current_pct: 10,
            threshold_pct: 15,
        };
        let estimate = DepletionEstimate {
            consumable: ConsumableKind::TonerBlack,
            avg_daily_consumption: 1.0,
            days_until_empty: Some(5.0),
            current_level_pct: 10,
        };
        let config = SupplyConfig::default();
        let order = evaluate_triggers(Some(&alert), Some(&estimate), &test_printer(), &config);
        assert!(order.is_some());
        assert_eq!(order.unwrap().trigger, ReorderTrigger::Threshold);
    }
}
