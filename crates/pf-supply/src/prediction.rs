// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Consumption prediction using a 90-day moving average model.
//!
//! Given a time series of supply level readings, this module computes
//! average daily consumption and estimates the number of days until
//! the supply reaches zero.

use chrono::{DateTime, Utc};

use crate::config::PredictionConfig;
use crate::error::SupplyError;
use crate::monitoring::ConsumableKind;

/// A single supply-level data point.
#[derive(Debug, Clone)]
pub struct LevelReading {
    /// Timestamp of the reading.
    pub timestamp: DateTime<Utc>,
    /// Supply level at that time (0–100).
    pub level_pct: u8,
}

/// Result of the consumption prediction model.
#[derive(Debug, Clone)]
pub struct DepletionEstimate {
    /// Which consumable was analyzed.
    pub consumable: ConsumableKind,
    /// Average daily consumption in percentage points per day.
    pub avg_daily_consumption: f64,
    /// Estimated days until the supply reaches 0%.
    /// `None` if consumption rate is zero or negative (supply increasing).
    pub days_until_empty: Option<f64>,
    /// The most recent level reading used.
    pub current_level_pct: u8,
}

/// Estimate days until depletion using a moving-average consumption model.
///
/// Readings must be sorted by timestamp (oldest first). The function
/// considers only readings within the configured window.
///
/// # Errors
///
/// Returns [`SupplyError::InsufficientData`] if fewer than
/// `config.min_data_points` readings are available.
pub fn estimate_depletion(
    consumable: ConsumableKind,
    readings: &[LevelReading],
    config: &PredictionConfig,
) -> Result<DepletionEstimate, SupplyError> {
    if readings.len() < config.min_data_points {
        return Err(SupplyError::InsufficientData {
            required: config.min_data_points,
            available: readings.len(),
        });
    }

    // Filter to the configured window (most recent N days).
    let window_readings = filter_to_window(readings, config.window_days);

    if window_readings.len() < config.min_data_points {
        return Err(SupplyError::InsufficientData {
            required: config.min_data_points,
            available: window_readings.len(),
        });
    }

    let first = &window_readings[0];
    let last = &window_readings[window_readings.len() - 1];

    #[allow(clippy::cast_precision_loss)]
    let elapsed_days = (last.timestamp - first.timestamp).num_seconds() as f64 / 86_400.0;

    if elapsed_days <= 0.0 {
        return Ok(DepletionEstimate {
            consumable,
            avg_daily_consumption: 0.0,
            days_until_empty: None,
            current_level_pct: last.level_pct,
        });
    }

    // Consumption = how much the level dropped.
    let level_drop = f64::from(first.level_pct) - f64::from(last.level_pct);
    let avg_daily = level_drop / elapsed_days;

    let days_until_empty = if avg_daily > 0.0 {
        Some(f64::from(last.level_pct) / avg_daily)
    } else {
        None
    };

    Ok(DepletionEstimate {
        consumable,
        avg_daily_consumption: avg_daily,
        days_until_empty,
        current_level_pct: last.level_pct,
    })
}

/// Filter readings to those within the last `window_days` from the most
/// recent reading.
fn filter_to_window(readings: &[LevelReading], window_days: usize) -> Vec<&LevelReading> {
    if readings.is_empty() {
        return Vec::new();
    }
    let latest = readings[readings.len() - 1].timestamp;
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = latest - chrono::Duration::days(window_days as i64);
    readings.iter().filter(|r| r.timestamp >= cutoff).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_readings(pairs: &[(i64, u8)]) -> Vec<LevelReading> {
        pairs
            .iter()
            .map(|&(day_offset, level)| LevelReading {
                timestamp: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
                    + chrono::Duration::days(day_offset),
                level_pct: level,
            })
            .collect()
    }

    #[test]
    fn insufficient_data_returns_error() {
        let config = PredictionConfig {
            window_days: 90,
            min_data_points: 7,
        };
        let readings = make_readings(&[(0, 100), (1, 98)]);
        let result = estimate_depletion(ConsumableKind::TonerBlack, &readings, &config);
        assert!(result.is_err());
    }

    #[test]
    fn linear_consumption_predicts_correctly() {
        let config = PredictionConfig {
            window_days: 90,
            min_data_points: 2,
        };
        // 100% on day 0, 50% on day 50 -> 1%/day -> 50 days remaining
        let readings = make_readings(&[(0, 100), (10, 90), (20, 80), (30, 70), (40, 60), (50, 50)]);
        let est = estimate_depletion(ConsumableKind::TonerBlack, &readings, &config).unwrap();

        let days = est.days_until_empty.unwrap();
        assert!((days - 50.0).abs() < 0.1, "expected ~50 days, got {days}");
        assert!((est.avg_daily_consumption - 1.0).abs() < 0.01);
    }

    #[test]
    fn zero_consumption_returns_none() {
        let config = PredictionConfig {
            window_days: 90,
            min_data_points: 2,
        };
        let readings = make_readings(&[(0, 80), (10, 80), (20, 80)]);
        let est = estimate_depletion(ConsumableKind::TonerBlack, &readings, &config).unwrap();
        assert!(est.days_until_empty.is_none());
    }

    #[test]
    fn increasing_level_returns_none() {
        // Level going up (e.g., toner replaced) — no depletion estimate.
        let config = PredictionConfig {
            window_days: 90,
            min_data_points: 2,
        };
        let readings = make_readings(&[(0, 10), (5, 50), (10, 100)]);
        let est = estimate_depletion(ConsumableKind::TonerBlack, &readings, &config).unwrap();
        assert!(est.days_until_empty.is_none());
    }
}
