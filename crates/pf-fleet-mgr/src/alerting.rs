// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Alert evaluation and routing types.
//!
//! Evaluates printer health data against configured thresholds and generates
//! alerts routed via email, Teams, SNMP trap, or the admin UI.
//!
//! **NIST 800-53 Rev 5:** SI-4 — System Monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterId;

use crate::config::AlertThresholds;
use crate::health::HealthScore;

/// Severity level of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational — no action required.
    Info,
    /// Warning — attention recommended.
    Warning,
    /// Critical — immediate action required.
    Critical,
}

/// Category of alert condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertCategory {
    /// Printer went offline.
    PrinterOffline,
    /// Printer is in error state.
    PrinterError,
    /// Toner supply is low.
    TonerLow,
    /// Paper supply is low.
    PaperLow,
    /// Health score degraded below threshold.
    HealthDegraded,
    /// Firmware is out of date.
    FirmwareOutdated,
    /// STIG violation detected (e.g., SNMPv1/v2c).
    StigViolation,
}

/// A generated alert for a printer condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAlert {
    /// Unique alert identifier.
    pub id: Uuid,
    /// Printer that triggered this alert.
    pub printer_id: PrinterId,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Alert category.
    pub category: AlertCategory,
    /// Human-readable summary.
    pub summary: String,
    /// Detailed description with context.
    pub detail: Option<String>,
    /// When the alert was generated.
    pub generated_at: DateTime<Utc>,
    /// Whether the alert has been acknowledged.
    pub acknowledged: bool,
    /// When the alert was acknowledged, if applicable.
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// Destination for alert delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertRoute {
    /// Send via email.
    Email {
        /// Recipient email addresses.
        recipients: Vec<String>,
    },
    /// Send to a Microsoft Teams webhook.
    Teams {
        /// Webhook URL.
        webhook_url: String,
    },
    /// Forward as an SNMP trap.
    SnmpTrap {
        /// Trap receiver address.
        receiver: String,
    },
    /// Display in the admin UI.
    AdminUi,
}

/// Configuration mapping alert severities to routing destinations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRoutingConfig {
    /// Routes for critical alerts.
    pub critical: Vec<AlertRoute>,
    /// Routes for warning alerts.
    pub warning: Vec<AlertRoute>,
    /// Routes for informational alerts.
    pub info: Vec<AlertRoute>,
}

/// Evaluate supply levels against thresholds and return any triggered alerts.
///
/// **NIST 800-53 Rev 5:** SI-4 — System Monitoring
#[must_use]
pub fn evaluate_supply_alerts(
    printer_id: &PrinterId,
    toner_min_pct: u8,
    paper_pct: u8,
    thresholds: &AlertThresholds,
) -> Vec<FleetAlert> {
    let mut alerts = Vec::new();
    let now = Utc::now();

    if toner_min_pct <= thresholds.toner_critical_pct {
        alerts.push(FleetAlert {
            id: Uuid::new_v4(),
            printer_id: printer_id.clone(),
            severity: AlertSeverity::Critical,
            category: AlertCategory::TonerLow,
            summary: format!(
                "Toner critically low at {toner_min_pct}% (threshold: {}%)",
                thresholds.toner_critical_pct
            ),
            detail: None,
            generated_at: now,
            acknowledged: false,
            acknowledged_at: None,
        });
    } else if toner_min_pct <= thresholds.toner_warning_pct {
        alerts.push(FleetAlert {
            id: Uuid::new_v4(),
            printer_id: printer_id.clone(),
            severity: AlertSeverity::Warning,
            category: AlertCategory::TonerLow,
            summary: format!(
                "Toner low at {toner_min_pct}% (threshold: {}%)",
                thresholds.toner_warning_pct
            ),
            detail: None,
            generated_at: now,
            acknowledged: false,
            acknowledged_at: None,
        });
    }

    if paper_pct <= thresholds.paper_critical_pct {
        alerts.push(FleetAlert {
            id: Uuid::new_v4(),
            printer_id: printer_id.clone(),
            severity: AlertSeverity::Critical,
            category: AlertCategory::PaperLow,
            summary: format!(
                "Paper critically low at {paper_pct}% (threshold: {}%)",
                thresholds.paper_critical_pct
            ),
            detail: None,
            generated_at: now,
            acknowledged: false,
            acknowledged_at: None,
        });
    } else if paper_pct <= thresholds.paper_warning_pct {
        alerts.push(FleetAlert {
            id: Uuid::new_v4(),
            printer_id: printer_id.clone(),
            severity: AlertSeverity::Warning,
            category: AlertCategory::PaperLow,
            summary: format!(
                "Paper low at {paper_pct}% (threshold: {}%)",
                thresholds.paper_warning_pct
            ),
            detail: None,
            generated_at: now,
            acknowledged: false,
            acknowledged_at: None,
        });
    }

    alerts
}

/// Evaluate a health score against thresholds and return any triggered alerts.
///
/// **NIST 800-53 Rev 5:** SI-4 — System Monitoring
#[must_use]
pub fn evaluate_health_alerts(
    printer_id: &PrinterId,
    health: &HealthScore,
    thresholds: &AlertThresholds,
) -> Vec<FleetAlert> {
    let mut alerts = Vec::new();
    let now = Utc::now();

    if health.overall <= thresholds.health_critical_score {
        alerts.push(FleetAlert {
            id: Uuid::new_v4(),
            printer_id: printer_id.clone(),
            severity: AlertSeverity::Critical,
            category: AlertCategory::HealthDegraded,
            summary: format!(
                "Health score critically low at {} (threshold: {})",
                health.overall, thresholds.health_critical_score
            ),
            detail: Some(format!(
                "Breakdown — connectivity: {}, error: {}, supply: {}, queue: {}, firmware: {}",
                health.breakdown.connectivity,
                health.breakdown.error_state,
                health.breakdown.supply_levels,
                health.breakdown.queue_depth,
                health.breakdown.firmware_currency,
            )),
            generated_at: now,
            acknowledged: false,
            acknowledged_at: None,
        });
    } else if health.overall <= thresholds.health_degraded_score {
        alerts.push(FleetAlert {
            id: Uuid::new_v4(),
            printer_id: printer_id.clone(),
            severity: AlertSeverity::Warning,
            category: AlertCategory::HealthDegraded,
            summary: format!(
                "Health score degraded at {} (threshold: {})",
                health.overall, thresholds.health_degraded_score
            ),
            detail: None,
            generated_at: now,
            acknowledged: false,
            acknowledged_at: None,
        });
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthBreakdown;

    fn test_printer_id() -> PrinterId {
        PrinterId::new("PRN-0001").unwrap()
    }

    fn default_thresholds() -> AlertThresholds {
        AlertThresholds::default()
    }

    #[test]
    fn nist_si4_critical_toner_generates_critical_alert() {
        // NIST SI-4: System Monitoring
        let alerts = evaluate_supply_alerts(&test_printer_id(), 3, 50, &default_thresholds());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(alerts[0].category, AlertCategory::TonerLow);
    }

    #[test]
    fn nist_si4_warning_toner_generates_warning_alert() {
        // NIST SI-4: System Monitoring
        let alerts = evaluate_supply_alerts(&test_printer_id(), 15, 50, &default_thresholds());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
    }

    #[test]
    fn no_alert_when_supplies_are_healthy() {
        let alerts = evaluate_supply_alerts(&test_printer_id(), 80, 70, &default_thresholds());
        assert!(alerts.is_empty());
    }

    #[test]
    fn both_toner_and_paper_can_alert() {
        let alerts = evaluate_supply_alerts(&test_printer_id(), 3, 3, &default_thresholds());
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn nist_si4_critical_health_generates_critical_alert() {
        // NIST SI-4: System Monitoring
        let health = HealthScore {
            overall: 20,
            breakdown: HealthBreakdown {
                connectivity: 0,
                error_state: 0,
                supply_levels: 50,
                queue_depth: 80,
                firmware_currency: 40,
            },
        };
        let alerts = evaluate_health_alerts(&test_printer_id(), &health, &default_thresholds());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn warning_health_generates_warning_alert() {
        let health = HealthScore {
            overall: 50,
            breakdown: HealthBreakdown {
                connectivity: 60,
                error_state: 50,
                supply_levels: 40,
                queue_depth: 50,
                firmware_currency: 40,
            },
        };
        let alerts = evaluate_health_alerts(&test_printer_id(), &health, &default_thresholds());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
    }

    #[test]
    fn no_alert_for_healthy_score() {
        let health = HealthScore {
            overall: 95,
            breakdown: HealthBreakdown {
                connectivity: 100,
                error_state: 100,
                supply_levels: 80,
                queue_depth: 90,
                firmware_currency: 100,
            },
        };
        let alerts = evaluate_health_alerts(&test_printer_id(), &health, &default_thresholds());
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
    }
}
