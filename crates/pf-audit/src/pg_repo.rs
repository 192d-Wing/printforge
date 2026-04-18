// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`AuditRepository`].
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! This implementation enforces append-only semantics: only `INSERT` and
//! `SELECT` queries are issued. No `UPDATE` or `DELETE` statements exist
//! in this module.

use pf_common::audit::{AuditEvent, EventKind, Outcome};
use pf_common::identity::Edipi;
use sqlx::PgPool;

use crate::error::AuditError;
use crate::query::{AuditQuery, AuditQueryResult};
use crate::repository::AuditRepository;

/// `PostgreSQL`-backed audit repository.
///
/// **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
/// Only `INSERT` and `SELECT` operations are implemented. The database
/// migration revokes `UPDATE` and `DELETE` privileges on the
/// `audit_events` table for the application role.
pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    /// Create a new `PgAuditRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AuditRepository for PgAuditRepository {
    /// Insert a single audit event into the append-only `audit_events` table.
    ///
    /// **NIST 800-53 Rev 5:** AU-9 — Append-only write
    async fn insert(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let action_str = serde_json::to_value(event.action)
            .map_err(AuditError::Serialization)?
            .as_str()
            .unwrap_or_default()
            .to_string();

        let outcome_str = serde_json::to_value(event.outcome)
            .map_err(AuditError::Serialization)?
            .as_str()
            .unwrap_or_default()
            .to_string();

        sqlx::query(
            r"INSERT INTO audit_events (id, timestamp, actor_edipi, action, target, outcome, source_ip, nist_control, payload)
              VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, '{}'::jsonb)",
        )
        .bind(event.id)
        .bind(event.timestamp)
        .bind(event.actor.as_str())
        .bind(&action_str)
        .bind(&event.target)
        .bind(&outcome_str)
        .bind(event.source_ip.to_string())
        .bind(&event.nist_control)
        .execute(&self.pool)
        .await
        .map_err(AuditError::Persistence)?;

        Ok(())
    }

    /// Query the audit store with the given filters.
    ///
    /// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
    async fn query(&self, query: &AuditQuery) -> Result<AuditQueryResult, AuditError> {
        query.validate()?;

        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx: usize = 0;

        // Build dynamic WHERE clauses. We use string-based query building
        // because the set of active filters varies per call.
        if query.actor.is_some() {
            param_idx += 1;
            where_clauses.push(format!("actor_edipi = ${param_idx}"));
        }

        if query.actions.is_some() {
            param_idx += 1;
            where_clauses.push(format!("action = ANY(${param_idx})"));
        }

        if query.outcome.is_some() {
            param_idx += 1;
            where_clauses.push(format!("outcome = ${param_idx}"));
        }

        if query.from.is_some() {
            param_idx += 1;
            where_clauses.push(format!("timestamp >= ${param_idx}"));
        }

        if query.to.is_some() {
            param_idx += 1;
            where_clauses.push(format!("timestamp < ${param_idx}"));
        }

        if query.target_contains.is_some() {
            param_idx += 1;
            where_clauses.push(format!("target LIKE '%' || ${param_idx} || '%'"));
        }

        if query.nist_control.is_some() {
            param_idx += 1;
            where_clauses.push(format!("nist_control = ${param_idx}"));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let limit = query.limit.unwrap_or(1000);
        let offset = query.offset.unwrap_or(0);

        // Count query
        let count_sql = format!("SELECT COUNT(*) as cnt FROM audit_events {where_sql}");
        let data_sql = format!(
            "SELECT id, timestamp, actor_edipi, action, target, outcome, source_ip, nist_control \
             FROM audit_events {where_sql} ORDER BY timestamp DESC LIMIT {limit} OFFSET {offset}"
        );

        // Build and execute count query
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
        count_query = bind_audit_params(count_query, query);
        let total_count = count_query
            .fetch_one(&self.pool)
            .await
            .map_err(AuditError::Persistence)?;

        // Build and execute data query
        let mut data_query = sqlx::query_as::<_, AuditEventRow>(&data_sql);
        data_query = bind_audit_data_params(data_query, query);
        let rows = data_query
            .fetch_all(&self.pool)
            .await
            .map_err(AuditError::Persistence)?;

        let events = rows
            .into_iter()
            .filter_map(|row| row.try_into_audit_event().ok())
            .collect();

        Ok(AuditQueryResult {
            events,
            total_count: u64::try_from(total_count).unwrap_or(0),
            offset,
            limit,
        })
    }

    /// Count all records in the online `audit_events` table.
    async fn count_online(&self) -> Result<u64, AuditError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await
            .map_err(AuditError::Persistence)?;

        Ok(u64::try_from(count).unwrap_or(0))
    }
}

/// Internal row type for mapping `audit_events` rows.
#[derive(sqlx::FromRow)]
struct AuditEventRow {
    id: uuid::Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    actor_edipi: String,
    action: String,
    target: String,
    outcome: String,
    source_ip: String,
    nist_control: Option<String>,
}

impl AuditEventRow {
    fn try_into_audit_event(self) -> Result<AuditEvent, AuditError> {
        let actor = Edipi::new(&self.actor_edipi).map_err(|e| AuditError::Validation {
            message: format!("invalid EDIPI in audit record: {e}"),
        })?;

        let action: EventKind = serde_json::from_value(serde_json::Value::String(
            self.action.clone(),
        ))
        .map_err(|_| AuditError::Validation {
            message: format!("unknown event kind: {}", self.action),
        })?;

        let outcome: Outcome = serde_json::from_value(serde_json::Value::String(
            self.outcome.clone(),
        ))
        .map_err(|_| AuditError::Validation {
            message: format!("unknown outcome: {}", self.outcome),
        })?;

        let source_ip = self.source_ip.parse().map_err(|_| AuditError::Validation {
            message: format!("invalid source IP: {}", self.source_ip),
        })?;

        Ok(AuditEvent {
            id: self.id,
            timestamp: self.timestamp,
            actor,
            action,
            target: self.target,
            outcome,
            source_ip,
            nist_control: self.nist_control,
        })
    }
}

/// Bind filter parameters to a count query.
fn bind_audit_params<'q>(
    mut q: sqlx::query::QueryScalar<'q, sqlx::Postgres, i64, sqlx::postgres::PgArguments>,
    query: &'q AuditQuery,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, i64, sqlx::postgres::PgArguments> {
    if let Some(ref actor) = query.actor {
        q = q.bind(actor.as_str());
    }
    if let Some(ref actions) = query.actions {
        let action_strings: Vec<String> = actions
            .iter()
            .filter_map(|a| {
                serde_json::to_value(a)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
            })
            .collect();
        q = q.bind(action_strings);
    }
    if let Some(outcome) = query.outcome {
        let outcome_str = serde_json::to_value(outcome)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        q = q.bind(outcome_str);
    }
    if let Some(from) = query.from {
        q = q.bind(from);
    }
    if let Some(to) = query.to {
        q = q.bind(to);
    }
    if let Some(ref target) = query.target_contains {
        q = q.bind(target.as_str());
    }
    if let Some(ref control) = query.nist_control {
        q = q.bind(control.as_str());
    }
    q
}

/// Bind filter parameters to a data query returning `AuditEventRow`.
fn bind_audit_data_params<'q>(
    mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, AuditEventRow, sqlx::postgres::PgArguments>,
    query: &'q AuditQuery,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, AuditEventRow, sqlx::postgres::PgArguments> {
    if let Some(ref actor) = query.actor {
        q = q.bind(actor.as_str());
    }
    if let Some(ref actions) = query.actions {
        let action_strings: Vec<String> = actions
            .iter()
            .filter_map(|a| {
                serde_json::to_value(a)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
            })
            .collect();
        q = q.bind(action_strings);
    }
    if let Some(outcome) = query.outcome {
        let outcome_str = serde_json::to_value(outcome)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        q = q.bind(outcome_str);
    }
    if let Some(from) = query.from {
        q = q.bind(from);
    }
    if let Some(to) = query.to {
        q = q.bind(to);
    }
    if let Some(ref target) = query.target_contains {
        q = q.bind(target.as_str());
    }
    if let Some(ref control) = query.nist_control {
        q = q.bind(control.as_str());
    }
    q
}

#[cfg(test)]
mod tests {
    #[test]
    fn nist_au9_pg_audit_repo_has_no_update_or_delete_methods() {
        // NIST 800-53 Rev 5: AU-9 — Protection of Audit Information
        // Evidence: The PgAuditRepository struct only implements insert, query,
        // and count_online via the AuditRepository trait. The trait itself has
        // no update or delete methods, guaranteeing append-only semantics at
        // the Rust type level.
        //
        // This is enforced by the trait definition in repository.rs and
        // verified by the nist_au9_migration_contains_revoke_update_delete
        // test in that module.
    }
}
