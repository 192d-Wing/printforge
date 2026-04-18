// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`AlertRepository`].
//!
//! **NIST 800-53 Rev 5:** SI-4 — System Monitoring

use chrono::Utc;
use pf_common::fleet::PrinterId;
use sqlx::PgPool;
use uuid::Uuid;

use crate::alert_store::{AlertRepository, AlertState, StoredAlert};
use crate::alerting::{AlertCategory, AlertSeverity};
use crate::error::FleetError;

/// `PostgreSQL`-backed alerts repository.
pub struct PgAlertRepository {
    pool: PgPool,
}

impl PgAlertRepository {
    /// Create a new `PgAlertRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Internal row type mirroring the `alerts` table.
#[derive(sqlx::FromRow)]
struct AlertRow {
    id: Uuid,
    printer_id: String,
    site_id: String,
    severity: String,
    category: String,
    state: String,
    summary: String,
    detail: Option<String>,
    generated_at: chrono::DateTime<chrono::Utc>,
    acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    acknowledged_by: Option<String>,
    resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AlertRow {
    fn try_into_stored(self) -> Result<StoredAlert, FleetError> {
        Ok(StoredAlert {
            id: self.id,
            printer_id: PrinterId::new(&self.printer_id)?,
            site_id: self.site_id,
            severity: parse_severity(&self.severity)?,
            category: parse_category(&self.category)?,
            state: parse_state(&self.state)?,
            summary: self.summary,
            detail: self.detail,
            generated_at: self.generated_at,
            acknowledged_at: self.acknowledged_at,
            acknowledged_by: self.acknowledged_by,
            resolved_at: self.resolved_at,
        })
    }
}

fn severity_to_str(s: AlertSeverity) -> &'static str {
    match s {
        AlertSeverity::Info => "Info",
        AlertSeverity::Warning => "Warning",
        AlertSeverity::Critical => "Critical",
    }
}

fn parse_severity(s: &str) -> Result<AlertSeverity, FleetError> {
    match s {
        "Info" => Ok(AlertSeverity::Info),
        "Warning" => Ok(AlertSeverity::Warning),
        "Critical" => Ok(AlertSeverity::Critical),
        other => Err(FleetError::Repository(sqlx::Error::Protocol(format!(
            "unknown alert severity: {other}"
        )))),
    }
}

fn category_to_str(c: AlertCategory) -> &'static str {
    match c {
        AlertCategory::PrinterOffline => "PrinterOffline",
        AlertCategory::PrinterError => "PrinterError",
        AlertCategory::TonerLow => "TonerLow",
        AlertCategory::PaperLow => "PaperLow",
        AlertCategory::HealthDegraded => "HealthDegraded",
        AlertCategory::FirmwareOutdated => "FirmwareOutdated",
        AlertCategory::StigViolation => "StigViolation",
    }
}

fn parse_category(s: &str) -> Result<AlertCategory, FleetError> {
    match s {
        "PrinterOffline" => Ok(AlertCategory::PrinterOffline),
        "PrinterError" => Ok(AlertCategory::PrinterError),
        "TonerLow" => Ok(AlertCategory::TonerLow),
        "PaperLow" => Ok(AlertCategory::PaperLow),
        "HealthDegraded" => Ok(AlertCategory::HealthDegraded),
        "FirmwareOutdated" => Ok(AlertCategory::FirmwareOutdated),
        "StigViolation" => Ok(AlertCategory::StigViolation),
        other => Err(FleetError::Repository(sqlx::Error::Protocol(format!(
            "unknown alert category: {other}"
        )))),
    }
}

fn state_to_str(s: AlertState) -> &'static str {
    match s {
        AlertState::Active => "Active",
        AlertState::Acknowledged => "Acknowledged",
        AlertState::Resolved => "Resolved",
    }
}

fn parse_state(s: &str) -> Result<AlertState, FleetError> {
    match s {
        "Active" => Ok(AlertState::Active),
        "Acknowledged" => Ok(AlertState::Acknowledged),
        "Resolved" => Ok(AlertState::Resolved),
        other => Err(FleetError::Repository(sqlx::Error::Protocol(format!(
            "unknown alert state: {other}"
        )))),
    }
}

const SELECT_COLUMNS: &str = "id, printer_id, site_id, severity, category, state, summary, \
    detail, generated_at, acknowledged_at, acknowledged_by, resolved_at";

impl AlertRepository for PgAlertRepository {
    async fn insert(&self, alert: &StoredAlert) -> Result<(), FleetError> {
        sqlx::query(
            "INSERT INTO alerts (id, printer_id, site_id, severity, category, state, \
             summary, detail, generated_at, acknowledged_at, acknowledged_by, resolved_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(alert.id)
        .bind(alert.printer_id.as_str())
        .bind(&alert.site_id)
        .bind(severity_to_str(alert.severity))
        .bind(category_to_str(alert.category))
        .bind(state_to_str(alert.state))
        .bind(&alert.summary)
        .bind(&alert.detail)
        .bind(alert.generated_at)
        .bind(alert.acknowledged_at)
        .bind(&alert.acknowledged_by)
        .bind(alert.resolved_at)
        .execute(&self.pool)
        .await
        .map_err(FleetError::Repository)?;
        Ok(())
    }

    async fn list_scoped(
        &self,
        installations: &[String],
        state_filter: Option<AlertState>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<StoredAlert>, u64), FleetError> {
        let state_str = state_filter.map(|s| state_to_str(s).to_string());

        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx: usize = 0;
        if state_str.is_some() {
            param_idx += 1;
            where_clauses.push(format!("state = ${param_idx}"));
        }
        if !installations.is_empty() {
            param_idx += 1;
            where_clauses.push(format!("site_id = ANY(${param_idx})"));
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let select_sql = format!(
            "SELECT {SELECT_COLUMNS} FROM alerts {where_sql} \
             ORDER BY generated_at DESC LIMIT ${lim} OFFSET ${off}",
            lim = param_idx + 1,
            off = param_idx + 2,
        );
        let count_sql = format!("SELECT COUNT(*)::bigint FROM alerts {where_sql}");

        let mut page_q = sqlx::query_as::<_, AlertRow>(&select_sql);
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
        if let Some(ref s) = state_str {
            page_q = page_q.bind(s);
            count_q = count_q.bind(s);
        }
        if !installations.is_empty() {
            page_q = page_q.bind(installations.to_vec());
            count_q = count_q.bind(installations.to_vec());
        }
        page_q = page_q.bind(i64::from(limit)).bind(i64::from(offset));

        let rows = page_q
            .fetch_all(&self.pool)
            .await
            .map_err(FleetError::Repository)?;
        let total = count_q
            .fetch_one(&self.pool)
            .await
            .map_err(FleetError::Repository)?;

        let alerts = rows
            .into_iter()
            .map(AlertRow::try_into_stored)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((alerts, u64::try_from(total).unwrap_or(0)))
    }

    async fn get_by_id(&self, id: Uuid) -> Result<StoredAlert, FleetError> {
        let row = sqlx::query_as::<_, AlertRow>(&format!(
            "SELECT {SELECT_COLUMNS} FROM alerts WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(FleetError::Repository)?
        .ok_or(FleetError::PrinterNotFound)?;

        row.try_into_stored()
    }

    async fn acknowledge(
        &self,
        id: Uuid,
        by_edipi: &str,
    ) -> Result<StoredAlert, FleetError> {
        let now = Utc::now();
        let rows_affected = sqlx::query(
            "UPDATE alerts SET state = 'Acknowledged', acknowledged_at = $1, \
             acknowledged_by = $2 WHERE id = $3 AND state = 'Active'",
        )
        .bind(now)
        .bind(by_edipi)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(FleetError::Repository)?
        .rows_affected();

        if rows_affected == 0 {
            // Either no such alert, or the alert is already in a non-Active
            // state. Re-read to surface the right error: a NotFound for the
            // missing case, or the current row so the caller can see the
            // terminal state.
            let existing = self.get_by_id(id).await?;
            return Ok(existing);
        }

        self.get_by_id(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_roundtrip() {
        for s in [AlertSeverity::Info, AlertSeverity::Warning, AlertSeverity::Critical] {
            let encoded = severity_to_str(s);
            assert_eq!(parse_severity(encoded).unwrap(), s);
        }
    }

    #[test]
    fn category_roundtrip() {
        for c in [
            AlertCategory::PrinterOffline,
            AlertCategory::PrinterError,
            AlertCategory::TonerLow,
            AlertCategory::PaperLow,
            AlertCategory::HealthDegraded,
            AlertCategory::FirmwareOutdated,
            AlertCategory::StigViolation,
        ] {
            let encoded = category_to_str(c);
            assert_eq!(parse_category(encoded).unwrap(), c);
        }
    }

    #[test]
    fn state_roundtrip() {
        for st in [AlertState::Active, AlertState::Acknowledged, AlertState::Resolved] {
            let encoded = state_to_str(st);
            assert_eq!(parse_state(encoded).unwrap(), st);
        }
    }
}
