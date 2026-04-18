// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`ReportRepository`].

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ReportError;
use crate::repository::ReportRepository;
use crate::types::{NewReport, ReportFormat, ReportKind, ReportRecord, ReportState};

/// `PostgreSQL`-backed reports repository.
pub struct PgReportRepository {
    pool: PgPool,
}

impl PgReportRepository {
    /// Create a new repository backed by the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ReportRow {
    id: Uuid,
    kind: String,
    format: String,
    requested_by: String,
    requested_at: chrono::DateTime<Utc>,
    site_id: String,
    start_date: chrono::NaiveDate,
    end_date: chrono::NaiveDate,
    state: String,
    row_count: Option<i64>,
    output_location: Option<String>,
    failure_reason: Option<String>,
    completed_at: Option<chrono::DateTime<Utc>>,
}

impl ReportRow {
    fn try_into_record(self) -> Result<ReportRecord, ReportError> {
        Ok(ReportRecord {
            id: self.id,
            kind: parse_kind(&self.kind)?,
            format: parse_format(&self.format)?,
            requested_by: self.requested_by,
            requested_at: self.requested_at,
            site_id: self.site_id,
            start_date: self.start_date,
            end_date: self.end_date,
            state: parse_state(&self.state)?,
            row_count: self.row_count.map(|n| u64::try_from(n).unwrap_or(0)),
            output_location: self.output_location,
            failure_reason: self.failure_reason,
            completed_at: self.completed_at,
        })
    }
}

fn kind_to_str(k: ReportKind) -> &'static str {
    match k {
        ReportKind::Chargeback => "Chargeback",
        ReportKind::Utilization => "Utilization",
        ReportKind::QuotaCompliance => "QuotaCompliance",
        ReportKind::WasteReduction => "WasteReduction",
    }
}

fn parse_kind(s: &str) -> Result<ReportKind, ReportError> {
    match s {
        "Chargeback" => Ok(ReportKind::Chargeback),
        "Utilization" => Ok(ReportKind::Utilization),
        "QuotaCompliance" => Ok(ReportKind::QuotaCompliance),
        "WasteReduction" => Ok(ReportKind::WasteReduction),
        other => Err(ReportError::Repository(sqlx::Error::Protocol(format!(
            "unknown report kind: {other}"
        )))),
    }
}

fn format_to_str(f: ReportFormat) -> &'static str {
    match f {
        ReportFormat::Json => "Json",
        ReportFormat::Csv => "Csv",
    }
}

fn parse_format(s: &str) -> Result<ReportFormat, ReportError> {
    match s {
        "Json" => Ok(ReportFormat::Json),
        "Csv" => Ok(ReportFormat::Csv),
        other => Err(ReportError::Repository(sqlx::Error::Protocol(format!(
            "unknown report format: {other}"
        )))),
    }
}

/// Map a state enum to its DB string — used by the worker transitions.
#[allow(dead_code)]
fn state_to_str(s: ReportState) -> &'static str {
    match s {
        ReportState::Pending => "Pending",
        ReportState::Generating => "Generating",
        ReportState::Ready => "Ready",
        ReportState::Failed => "Failed",
    }
}

fn parse_state(s: &str) -> Result<ReportState, ReportError> {
    match s {
        "Pending" => Ok(ReportState::Pending),
        "Generating" => Ok(ReportState::Generating),
        "Ready" => Ok(ReportState::Ready),
        "Failed" => Ok(ReportState::Failed),
        other => Err(ReportError::Repository(sqlx::Error::Protocol(format!(
            "unknown report state: {other}"
        )))),
    }
}

const SELECT_COLUMNS: &str = "id, kind, format, requested_by, requested_at, site_id, \
    start_date, end_date, state, row_count, output_location, failure_reason, completed_at";

impl ReportRepository for PgReportRepository {
    async fn enqueue(&self, new: &NewReport) -> Result<ReportRecord, ReportError> {
        let id = Uuid::now_v7();
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO reports (id, kind, format, requested_by, requested_at, \
             site_id, start_date, end_date, state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Pending')",
        )
        .bind(id)
        .bind(kind_to_str(new.kind))
        .bind(format_to_str(new.format))
        .bind(&new.requested_by)
        .bind(now)
        .bind(&new.site_id)
        .bind(new.start_date)
        .bind(new.end_date)
        .execute(&self.pool)
        .await
        .map_err(ReportError::Repository)?;

        Ok(ReportRecord {
            id,
            kind: new.kind,
            format: new.format,
            requested_by: new.requested_by.clone(),
            requested_at: now,
            site_id: new.site_id.clone(),
            start_date: new.start_date,
            end_date: new.end_date,
            state: ReportState::Pending,
            row_count: None,
            output_location: None,
            failure_reason: None,
            completed_at: None,
        })
    }

    async fn get_by_id(&self, id: Uuid) -> Result<ReportRecord, ReportError> {
        let row = sqlx::query_as::<_, ReportRow>(&format!(
            "SELECT {SELECT_COLUMNS} FROM reports WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ReportError::Repository)?
        .ok_or(ReportError::NotFound)?;

        row.try_into_record()
    }

    async fn claim_next_pending(&self) -> Result<Option<ReportRecord>, ReportError> {
        // SELECT ... FOR UPDATE SKIP LOCKED + CTE-based UPDATE so multiple
        // workers can run in parallel. The inner SELECT picks the oldest
        // Pending row; the UPDATE flips it to Generating and returns the
        // full row in a single round-trip.
        let row = sqlx::query_as::<_, ReportRow>(&format!(
            "WITH claimed AS (\
                SELECT id FROM reports \
                WHERE state = 'Pending' \
                ORDER BY requested_at \
                FOR UPDATE SKIP LOCKED \
                LIMIT 1\
             ) \
             UPDATE reports SET state = 'Generating' \
             FROM claimed WHERE reports.id = claimed.id \
             RETURNING {SELECT_COLUMNS}"
        ))
        .fetch_optional(&self.pool)
        .await
        .map_err(ReportError::Repository)?;

        row.map(ReportRow::try_into_record).transpose()
    }

    async fn mark_ready(
        &self,
        id: Uuid,
        row_count: u64,
        output_location: Option<String>,
    ) -> Result<(), ReportError> {
        let count_i64 = i64::try_from(row_count).unwrap_or(i64::MAX);
        let rows_affected = sqlx::query(
            "UPDATE reports SET state = 'Ready', row_count = $1, output_location = $2, \
             failure_reason = NULL, completed_at = NOW() WHERE id = $3",
        )
        .bind(count_i64)
        .bind(output_location)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(ReportError::Repository)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(ReportError::NotFound);
        }
        Ok(())
    }

    async fn mark_failed(&self, id: Uuid, reason: String) -> Result<(), ReportError> {
        let rows_affected = sqlx::query(
            "UPDATE reports SET state = 'Failed', failure_reason = $1, \
             completed_at = NOW() WHERE id = $2",
        )
        .bind(reason)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(ReportError::Repository)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(ReportError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_roundtrip() {
        for k in [
            ReportKind::Chargeback,
            ReportKind::Utilization,
            ReportKind::QuotaCompliance,
            ReportKind::WasteReduction,
        ] {
            assert_eq!(parse_kind(kind_to_str(k)).unwrap(), k);
        }
    }

    #[test]
    fn format_roundtrip() {
        for f in [ReportFormat::Json, ReportFormat::Csv] {
            assert_eq!(parse_format(format_to_str(f)).unwrap(), f);
        }
    }

    #[test]
    fn state_roundtrip() {
        for s in [
            ReportState::Pending,
            ReportState::Generating,
            ReportState::Ready,
            ReportState::Failed,
        ] {
            assert_eq!(parse_state(state_to_str(s)).unwrap(), s);
        }
    }
}
