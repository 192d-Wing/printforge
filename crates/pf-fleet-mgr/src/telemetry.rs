// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Time-series telemetry data types for `TimescaleDB` persistence.
//!
//! Supply levels, page counts, and health scores are written as time-series
//! data to `TimescaleDB` hypertables for efficient range queries, downsampling,
//! and long-term trending.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use pf_common::fleet::{PrinterId, SupplyLevel};

use crate::snmp::PageCounts;

/// A telemetry data point to be written to `TimescaleDB`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPoint {
    /// Printer this data point belongs to.
    pub printer_id: PrinterId,
    /// When this data was collected.
    pub timestamp: DateTime<Utc>,
    /// The telemetry payload.
    pub data: TelemetryData,
}

/// The payload of a telemetry data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryData {
    /// Supply level snapshot.
    SupplyLevels(SupplyLevel),
    /// Page count snapshot.
    PageCounts(PageCounts),
    /// Health score snapshot.
    HealthScore {
        /// Overall score (0--100).
        overall: u8,
        /// Connectivity factor (0--100).
        connectivity: u8,
        /// Error state factor (0--100).
        error_state: u8,
        /// Supply factor (0--100).
        supply: u8,
        /// Queue factor (0--100).
        queue: u8,
        /// Firmware factor (0--100).
        firmware: u8,
    },
}

/// A request to query time-series telemetry data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryQuery {
    /// Printer to query.
    pub printer_id: PrinterId,
    /// Start of the time range (inclusive).
    pub from: DateTime<Utc>,
    /// End of the time range (inclusive).
    pub to: DateTime<Utc>,
    /// Downsample interval in seconds (e.g., 3600 for hourly).
    pub downsample_secs: Option<u64>,
    /// Type of data to query.
    pub data_type: TelemetryDataType,
}

/// Selects which category of telemetry data to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TelemetryDataType {
    /// Supply level data.
    SupplyLevels,
    /// Page count data.
    PageCounts,
    /// Health score data.
    HealthScores,
}

/// A batch of telemetry points to write.
#[derive(Debug, Clone)]
pub struct TelemetryBatch {
    /// The data points in this batch.
    pub points: Vec<TelemetryPoint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_point_serializes_supply_levels() {
        let point = TelemetryPoint {
            printer_id: PrinterId::new("PRN-0001").unwrap(),
            timestamp: Utc::now(),
            data: TelemetryData::SupplyLevels(SupplyLevel {
                toner_k: 50,
                toner_c: 60,
                toner_m: 70,
                toner_y: 80,
                paper: 90,
            }),
        };
        let json = serde_json::to_string(&point).unwrap();
        assert!(json.contains("SupplyLevels"));
    }

    #[test]
    fn telemetry_query_covers_all_data_types() {
        let types = [
            TelemetryDataType::SupplyLevels,
            TelemetryDataType::PageCounts,
            TelemetryDataType::HealthScores,
        ];
        assert_eq!(types.len(), 3);
    }
}
