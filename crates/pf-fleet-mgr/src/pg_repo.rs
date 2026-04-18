// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`PrinterRepository`].
//!
//! **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
//! Maintains the authoritative printer inventory in `PostgreSQL`.

use std::net::IpAddr;

use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};
use sqlx::PgPool;

use crate::discovery::{DiscoveryMethod, PrinterLocation};
use crate::error::FleetError;
use crate::inventory::{FleetSummary, PrinterQuery, PrinterRecord, PrinterUpdate};
use crate::repository::PrinterRepository;

/// `PostgreSQL`-backed printer inventory repository.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
pub struct PgPrinterRepository {
    pool: PgPool,
}

impl PgPrinterRepository {
    /// Create a new `PgPrinterRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Internal row type for the `printers` table.
#[derive(sqlx::FromRow)]
struct PrinterRow {
    id: String,
    vendor: String,
    model: String,
    serial_number: String,
    firmware_version: String,
    ip_address: String,
    hostname: Option<String>,
    location_installation: String,
    location_building: String,
    location_floor: String,
    location_room: String,
    discovery_method: String,
    status: String,
    toner_k: Option<i16>,
    toner_c: Option<i16>,
    toner_m: Option<i16>,
    toner_y: Option<i16>,
    paper: Option<i16>,
    health_score: Option<i16>,
    total_page_count: Option<i64>,
    registered_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
    consecutive_poll_failures: i32,
}

impl PrinterRow {
    fn try_into_record(self) -> Result<PrinterRecord, FleetError> {
        let id = PrinterId::new(&self.id)?;

        let ip_address: IpAddr = self.ip_address.parse().map_err(|_| {
            FleetError::Repository(sqlx::Error::Protocol(format!(
                "invalid IP address in DB: {}",
                self.ip_address
            )))
        })?;

        let status = parse_printer_status(&self.status)?;
        let discovery_method = parse_discovery_method(&self.discovery_method)?;

        let supply_levels = match (
            self.toner_k,
            self.toner_c,
            self.toner_m,
            self.toner_y,
            self.paper,
        ) {
            (Some(tk), Some(tc), Some(tm), Some(ty), Some(pp)) => Some(SupplyLevel {
                toner_k: u8::try_from(tk).unwrap_or(0),
                toner_c: u8::try_from(tc).unwrap_or(0),
                toner_m: u8::try_from(tm).unwrap_or(0),
                toner_y: u8::try_from(ty).unwrap_or(0),
                paper: u8::try_from(pp).unwrap_or(0),
            }),
            _ => None,
        };

        Ok(PrinterRecord {
            id,
            model: PrinterModel {
                vendor: self.vendor,
                model: self.model,
            },
            serial_number: self.serial_number,
            firmware_version: self.firmware_version,
            ip_address,
            hostname: self.hostname,
            location: PrinterLocation {
                installation: self.location_installation,
                building: self.location_building,
                floor: self.location_floor,
                room: self.location_room,
            },
            discovery_method,
            status,
            supply_levels,
            health_score: self.health_score.map(|h| u8::try_from(h).unwrap_or(0)),
            total_page_count: self.total_page_count.map(|c| u64::try_from(c).unwrap_or(0)),
            registered_at: self.registered_at,
            updated_at: self.updated_at,
            last_polled_at: self.last_polled_at,
            consecutive_poll_failures: u32::try_from(self.consecutive_poll_failures).unwrap_or(0),
        })
    }
}

fn status_to_str(status: PrinterStatus) -> &'static str {
    match status {
        PrinterStatus::Online => "Online",
        PrinterStatus::Offline => "Offline",
        PrinterStatus::Error => "Error",
        PrinterStatus::Maintenance => "Maintenance",
        PrinterStatus::Printing => "Printing",
    }
}

fn parse_printer_status(s: &str) -> Result<PrinterStatus, FleetError> {
    match s {
        "Online" => Ok(PrinterStatus::Online),
        "Offline" => Ok(PrinterStatus::Offline),
        "Error" => Ok(PrinterStatus::Error),
        "Maintenance" => Ok(PrinterStatus::Maintenance),
        "Printing" => Ok(PrinterStatus::Printing),
        other => Err(FleetError::Repository(sqlx::Error::Protocol(format!(
            "unknown printer status: {other}"
        )))),
    }
}

fn parse_discovery_method(s: &str) -> Result<DiscoveryMethod, FleetError> {
    match s {
        "SnmpV3Walk" => Ok(DiscoveryMethod::SnmpV3Walk),
        "DnsSd" => Ok(DiscoveryMethod::DnsSd),
        "Manual" => Ok(DiscoveryMethod::Manual),
        other => Err(FleetError::Repository(sqlx::Error::Protocol(format!(
            "unknown discovery method: {other}"
        )))),
    }
}

fn discovery_method_to_str(method: DiscoveryMethod) -> &'static str {
    match method {
        DiscoveryMethod::SnmpV3Walk => "SnmpV3Walk",
        DiscoveryMethod::DnsSd => "DnsSd",
        DiscoveryMethod::Manual => "Manual",
    }
}

impl PrinterRepository for PgPrinterRepository {
    async fn insert(&self, record: &PrinterRecord) -> Result<(), FleetError> {
        sqlx::query(
            "INSERT INTO printers (id, vendor, model, serial_number, firmware_version, \
             ip_address, hostname, location_installation, location_building, location_floor, \
             location_room, discovery_method, status, toner_k, toner_c, toner_m, toner_y, \
             paper, health_score, total_page_count, registered_at, updated_at, last_polled_at, \
             consecutive_poll_failures) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                     $16, $17, $18, $19, $20, $21, $22, $23, $24)",
        )
        .bind(record.id.as_str())
        .bind(&record.model.vendor)
        .bind(&record.model.model)
        .bind(&record.serial_number)
        .bind(&record.firmware_version)
        .bind(record.ip_address.to_string())
        .bind(&record.hostname)
        .bind(&record.location.installation)
        .bind(&record.location.building)
        .bind(&record.location.floor)
        .bind(&record.location.room)
        .bind(discovery_method_to_str(record.discovery_method))
        .bind(status_to_str(record.status))
        .bind(record.supply_levels.map(|s| i16::from(s.toner_k)))
        .bind(record.supply_levels.map(|s| i16::from(s.toner_c)))
        .bind(record.supply_levels.map(|s| i16::from(s.toner_m)))
        .bind(record.supply_levels.map(|s| i16::from(s.toner_y)))
        .bind(record.supply_levels.map(|s| i16::from(s.paper)))
        .bind(record.health_score.map(i16::from))
        .bind(
            record
                .total_page_count
                .map(|c| i64::try_from(c).unwrap_or(i64::MAX)),
        )
        .bind(record.registered_at)
        .bind(record.updated_at)
        .bind(record.last_polled_at)
        .bind(i32::try_from(record.consecutive_poll_failures).unwrap_or(0))
        .execute(&self.pool)
        .await
        .map_err(FleetError::Repository)?;

        Ok(())
    }

    async fn get_by_id(&self, id: &PrinterId) -> Result<PrinterRecord, FleetError> {
        let row = sqlx::query_as::<_, PrinterRow>(
            "SELECT id, vendor, model, serial_number, firmware_version, ip_address, hostname, \
             location_installation, location_building, location_floor, location_room, \
             discovery_method, status, toner_k, toner_c, toner_m, toner_y, paper, \
             health_score, total_page_count, registered_at, updated_at, last_polled_at, \
             consecutive_poll_failures FROM printers WHERE id = $1",
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(FleetError::Repository)?
        .ok_or(FleetError::PrinterNotFound)?;

        row.try_into_record()
    }

    async fn update(&self, id: &PrinterId, update: &PrinterUpdate) -> Result<(), FleetError> {
        // Build a dynamic UPDATE query based on which fields are present.
        let mut set_clauses: Vec<String> = Vec::new();
        let mut param_idx: usize = 1;

        // Reserve $1 for the WHERE clause (id)
        if update.ip_address.is_some() {
            param_idx += 1;
            set_clauses.push(format!("ip_address = ${param_idx}"));
        }
        if update.hostname.is_some() {
            param_idx += 1;
            set_clauses.push(format!("hostname = ${param_idx}"));
        }
        if update.firmware_version.is_some() {
            param_idx += 1;
            set_clauses.push(format!("firmware_version = ${param_idx}"));
        }
        if update.location.is_some() {
            param_idx += 1;
            set_clauses.push(format!("location_installation = ${param_idx}"));
            param_idx += 1;
            set_clauses.push(format!("location_building = ${param_idx}"));
            param_idx += 1;
            set_clauses.push(format!("location_floor = ${param_idx}"));
            param_idx += 1;
            set_clauses.push(format!("location_room = ${param_idx}"));
        }
        if update.model.is_some() {
            param_idx += 1;
            set_clauses.push(format!("vendor = ${param_idx}"));
            param_idx += 1;
            set_clauses.push(format!("model = ${param_idx}"));
        }

        set_clauses.push("updated_at = NOW()".to_string());

        if set_clauses.len() == 1 {
            // Only updated_at, nothing to do.
            return Ok(());
        }

        let sql = format!(
            "UPDATE printers SET {} WHERE id = $1",
            set_clauses.join(", ")
        );

        let mut query = sqlx::query(&sql).bind(id.as_str());

        if let Some(ip) = update.ip_address {
            query = query.bind(ip.to_string());
        }
        if let Some(ref hostname) = update.hostname {
            query = query.bind(hostname.as_deref());
        }
        if let Some(ref fv) = update.firmware_version {
            query = query.bind(fv);
        }
        if let Some(ref loc) = update.location {
            query = query
                .bind(&loc.installation)
                .bind(&loc.building)
                .bind(&loc.floor)
                .bind(&loc.room);
        }
        if let Some(ref model) = update.model {
            query = query.bind(&model.vendor).bind(&model.model);
        }

        let result = query
            .execute(&self.pool)
            .await
            .map_err(FleetError::Repository)?;

        if result.rows_affected() == 0 {
            return Err(FleetError::PrinterNotFound);
        }

        Ok(())
    }

    async fn delete(&self, id: &PrinterId) -> Result<(), FleetError> {
        let result = sqlx::query("DELETE FROM printers WHERE id = $1")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(FleetError::Repository)?;

        if result.rows_affected() == 0 {
            return Err(FleetError::PrinterNotFound);
        }

        Ok(())
    }

    async fn query(&self, query: &PrinterQuery) -> Result<Vec<PrinterRecord>, FleetError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx: usize = 0;

        if query.installation.is_some() {
            param_idx += 1;
            where_clauses.push(format!("location_installation = ${param_idx}"));
        }
        if !query.installations.is_empty() {
            param_idx += 1;
            where_clauses.push(format!("location_installation = ANY(${param_idx})"));
        }
        if query.building.is_some() {
            param_idx += 1;
            where_clauses.push(format!("location_building = ${param_idx}"));
        }
        if query.status.is_some() {
            param_idx += 1;
            where_clauses.push(format!("status = ${param_idx}"));
        }
        if query.vendor.is_some() {
            param_idx += 1;
            where_clauses.push(format!("vendor = ${param_idx}"));
        }
        if query.model.is_some() {
            param_idx += 1;
            where_clauses.push(format!("model ILIKE '%' || ${param_idx} || '%'"));
        }
        if query.health_below.is_some() {
            param_idx += 1;
            where_clauses.push(format!("health_score < ${param_idx}"));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let limit = query.limit.unwrap_or(100);
        let offset = query.offset.unwrap_or(0);

        let sql = format!(
            "SELECT id, vendor, model, serial_number, firmware_version, ip_address, hostname, \
             location_installation, location_building, location_floor, location_room, \
             discovery_method, status, toner_k, toner_c, toner_m, toner_y, paper, \
             health_score, total_page_count, registered_at, updated_at, last_polled_at, \
             consecutive_poll_failures FROM printers {where_sql} \
             ORDER BY id LIMIT {limit} OFFSET {offset}"
        );

        let mut db_query = sqlx::query_as::<_, PrinterRow>(&sql);

        if let Some(ref installation) = query.installation {
            db_query = db_query.bind(installation);
        }
        if !query.installations.is_empty() {
            db_query = db_query.bind(query.installations.clone());
        }
        if let Some(ref building) = query.building {
            db_query = db_query.bind(building);
        }
        if let Some(status) = query.status {
            db_query = db_query.bind(status_to_str(status));
        }
        if let Some(ref vendor) = query.vendor {
            db_query = db_query.bind(vendor);
        }
        if let Some(ref model) = query.model {
            db_query = db_query.bind(model);
        }
        if let Some(health_below) = query.health_below {
            db_query = db_query.bind(i16::from(health_below));
        }

        let rows = db_query
            .fetch_all(&self.pool)
            .await
            .map_err(FleetError::Repository)?;

        rows.into_iter().map(PrinterRow::try_into_record).collect()
    }

    async fn summary(&self) -> Result<FleetSummary, FleetError> {
        let row = sqlx::query_as::<_, FleetSummaryRow>(
            "SELECT \
             COUNT(*)::bigint AS total_printers, \
             COUNT(*) FILTER (WHERE status = 'Online')::bigint AS online_count, \
             COUNT(*) FILTER (WHERE status = 'Offline')::bigint AS offline_count, \
             COUNT(*) FILTER (WHERE status = 'Error')::bigint AS error_count, \
             COUNT(*) FILTER (WHERE status = 'Maintenance')::bigint AS maintenance_count, \
             COALESCE(AVG(health_score), 0)::float8 AS average_health_score, \
             COUNT(*) FILTER (WHERE toner_k < 10 OR toner_c < 10 OR toner_m < 10 OR toner_y < 10 OR paper < 10)::bigint AS critical_supply_count \
             FROM printers",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(FleetError::Repository)?;

        Ok(FleetSummary {
            total_printers: u64::try_from(row.total_printers).unwrap_or(0),
            online_count: u64::try_from(row.online_count).unwrap_or(0),
            offline_count: u64::try_from(row.offline_count).unwrap_or(0),
            error_count: u64::try_from(row.error_count).unwrap_or(0),
            maintenance_count: u64::try_from(row.maintenance_count).unwrap_or(0),
            average_health_score: row.average_health_score,
            critical_supply_count: u64::try_from(row.critical_supply_count).unwrap_or(0),
        })
    }

    async fn list_ids(&self) -> Result<Vec<PrinterId>, FleetError> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT id FROM printers ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(FleetError::Repository)?;

        rows.into_iter()
            .map(|(id,)| PrinterId::new(&id).map_err(FleetError::Validation))
            .collect()
    }
}

/// Internal row type for fleet summary aggregation.
#[derive(sqlx::FromRow)]
struct FleetSummaryRow {
    total_printers: i64,
    online_count: i64,
    offline_count: i64,
    error_count: i64,
    maintenance_count: i64,
    average_health_score: f64,
    critical_supply_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_cm8_status_roundtrip() {
        // NIST 800-53 Rev 5: CM-8 — Status values persist correctly.
        let statuses = [
            PrinterStatus::Online,
            PrinterStatus::Offline,
            PrinterStatus::Error,
            PrinterStatus::Maintenance,
            PrinterStatus::Printing,
        ];
        for s in statuses {
            let str_val = status_to_str(s);
            let parsed = parse_printer_status(str_val).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn discovery_method_roundtrip() {
        let methods = [
            DiscoveryMethod::SnmpV3Walk,
            DiscoveryMethod::DnsSd,
            DiscoveryMethod::Manual,
        ];
        for m in methods {
            let str_val = discovery_method_to_str(m);
            let parsed = parse_discovery_method(str_val).unwrap();
            assert_eq!(parsed, m);
        }
    }
}
