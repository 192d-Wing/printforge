// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Supply-level monitoring and threshold evaluation.
//!
//! Consumes supply level telemetry (from `pf-fleet-mgr`) and checks
//! whether any consumable has dropped to or below its configured
//! reorder threshold.

use pf_common::fleet::{PrinterId, SupplyLevel};
use serde::{Deserialize, Serialize};

use crate::config::ThresholdConfig;

/// Identifies which consumable triggered the threshold alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsumableKind {
    /// Black toner cartridge.
    TonerBlack,
    /// Cyan toner cartridge.
    TonerCyan,
    /// Magenta toner cartridge.
    TonerMagenta,
    /// Yellow toner cartridge.
    TonerYellow,
    /// Paper supply.
    Paper,
}

impl std::fmt::Display for ConsumableKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TonerBlack => write!(f, "toner_k"),
            Self::TonerCyan => write!(f, "toner_c"),
            Self::TonerMagenta => write!(f, "toner_m"),
            Self::TonerYellow => write!(f, "toner_y"),
            Self::Paper => write!(f, "paper"),
        }
    }
}

/// A threshold breach detected during monitoring.
#[derive(Debug, Clone)]
pub struct ThresholdAlert {
    /// The printer whose supply is low.
    pub printer_id: PrinterId,
    /// Which consumable breached its threshold.
    pub consumable: ConsumableKind,
    /// Current level (0–100).
    pub current_pct: u8,
    /// The threshold that was breached.
    pub threshold_pct: u8,
}

/// Evaluate a printer's supply levels against configured thresholds.
///
/// Returns one [`ThresholdAlert`] per consumable that is at or below
/// its configured threshold.
///
/// # Errors
///
/// This function is infallible; it returns an empty `Vec` when all
/// levels are above their thresholds.
#[must_use]
pub fn check_thresholds(
    printer_id: &PrinterId,
    levels: &SupplyLevel,
    thresholds: &ThresholdConfig,
) -> Vec<ThresholdAlert> {
    let mut alerts = Vec::new();

    let toner_checks = [
        (ConsumableKind::TonerBlack, levels.toner_k),
        (ConsumableKind::TonerCyan, levels.toner_c),
        (ConsumableKind::TonerMagenta, levels.toner_m),
        (ConsumableKind::TonerYellow, levels.toner_y),
    ];

    for (kind, level) in toner_checks {
        if level <= thresholds.toner_pct {
            alerts.push(ThresholdAlert {
                printer_id: printer_id.clone(),
                consumable: kind,
                current_pct: level,
                threshold_pct: thresholds.toner_pct,
            });
        }
    }

    if levels.paper <= thresholds.paper_pct {
        alerts.push(ThresholdAlert {
            printer_id: printer_id.clone(),
            consumable: ConsumableKind::Paper,
            current_pct: levels.paper,
            threshold_pct: thresholds.paper_pct,
        });
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_printer_id() -> PrinterId {
        PrinterId::new("PRN-0001").unwrap()
    }

    #[test]
    fn no_alerts_when_all_levels_above_threshold() {
        let levels = SupplyLevel {
            toner_k: 80,
            toner_c: 60,
            toner_m: 50,
            toner_y: 70,
            paper: 90,
        };
        let thresholds = ThresholdConfig::default();
        let alerts = check_thresholds(&test_printer_id(), &levels, &thresholds);
        assert!(alerts.is_empty());
    }

    #[test]
    fn alert_when_toner_at_threshold() {
        let levels = SupplyLevel {
            toner_k: 15, // exactly at default threshold
            toner_c: 80,
            toner_m: 80,
            toner_y: 80,
            paper: 90,
        };
        let thresholds = ThresholdConfig::default();
        let alerts = check_thresholds(&test_printer_id(), &levels, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].consumable, ConsumableKind::TonerBlack);
        assert_eq!(alerts[0].current_pct, 15);
    }

    #[test]
    fn alert_when_paper_below_threshold() {
        let levels = SupplyLevel {
            toner_k: 80,
            toner_c: 80,
            toner_m: 80,
            toner_y: 80,
            paper: 10,
        };
        let thresholds = ThresholdConfig::default();
        let alerts = check_thresholds(&test_printer_id(), &levels, &thresholds);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].consumable, ConsumableKind::Paper);
    }

    #[test]
    fn multiple_alerts_when_multiple_consumables_low() {
        let levels = SupplyLevel {
            toner_k: 5,
            toner_c: 10,
            toner_m: 80,
            toner_y: 80,
            paper: 5,
        };
        let thresholds = ThresholdConfig::default();
        let alerts = check_thresholds(&test_printer_id(), &levels, &thresholds);
        assert_eq!(alerts.len(), 3);
    }
}
