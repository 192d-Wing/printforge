// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`SupplyRepository`].
//!
//! **NIST 800-53 Rev 5:** AU-9 -- Protection of Audit Information
//! Persists reorder requests, approval records, and vendor orders
//! in `PostgreSQL`.

use chrono::{DateTime, Utc};
use pf_common::fleet::PrinterId;
use sqlx::PgPool;
use uuid::Uuid;

use crate::approval::{ApprovalDecision, ApprovalLevel, ApprovalRequest};
use crate::error::SupplyError;
use crate::monitoring::ConsumableKind;
use crate::reorder::{ReorderRequest, ReorderStatus, ReorderTrigger};
use crate::repository::SupplyRepository;
use crate::vendor::VendorOrder;

/// `PostgreSQL`-backed supply chain repository.
///
/// **NIST 800-53 Rev 5:** AU-9
pub struct PgSupplyRepository {
    pool: PgPool,
}

impl PgSupplyRepository {
    /// Create a new `PgSupplyRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Internal row types
// ---------------------------------------------------------------------------

/// Row returned from the `supply_reorders` table.
#[derive(sqlx::FromRow)]
struct ReorderRow {
    id: Uuid,
    printer_id: String,
    consumable_kind: String,
    current_level_pct: i16,
    trigger_type: String,
    status: String,
    estimated_cost_cents: Option<i64>,
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    approved_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    submitted_at: Option<DateTime<Utc>>,
}

impl ReorderRow {
    fn try_into_request(self) -> Result<ReorderRequest, SupplyError> {
        let printer_id = PrinterId::new(&self.printer_id).map_err(SupplyError::Validation)?;
        let consumable = parse_consumable_kind(&self.consumable_kind)?;
        let trigger = parse_trigger_type(&self.trigger_type)?;
        let status = parse_reorder_status(&self.status)?;

        Ok(ReorderRequest {
            id: self.id,
            printer_id,
            consumable,
            trigger,
            current_level_pct: u8::try_from(self.current_level_pct).unwrap_or(0),
            estimated_cost_cents: self
                .estimated_cost_cents
                .and_then(|v| u64::try_from(v).ok()),
            status,
            created_at: self.created_at,
        })
    }
}

/// Row returned from the `supply_approvals` table.
#[allow(dead_code)]
#[derive(sqlx::FromRow)]
struct ApprovalRow {
    id: Uuid,
    reorder_id: Uuid,
    approver_edipi: String,
    level: String,
    decision: String,
    reason: Option<String>,
    decided_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_consumable_kind(s: &str) -> Result<ConsumableKind, SupplyError> {
    match s {
        "toner_k" | "TonerBlack" => Ok(ConsumableKind::TonerBlack),
        "toner_c" | "TonerCyan" => Ok(ConsumableKind::TonerCyan),
        "toner_m" | "TonerMagenta" => Ok(ConsumableKind::TonerMagenta),
        "toner_y" | "TonerYellow" => Ok(ConsumableKind::TonerYellow),
        "paper" | "Paper" => Ok(ConsumableKind::Paper),
        other => Err(SupplyError::Repository(sqlx::Error::Protocol(format!(
            "unknown consumable kind: {other}"
        )))),
    }
}

fn parse_trigger_type(s: &str) -> Result<ReorderTrigger, SupplyError> {
    match s {
        "Threshold" => Ok(ReorderTrigger::Threshold),
        "Predictive" => Ok(ReorderTrigger::Predictive),
        other => Err(SupplyError::Repository(sqlx::Error::Protocol(format!(
            "unknown trigger type: {other}"
        )))),
    }
}

fn reorder_trigger_to_str(t: &ReorderTrigger) -> &'static str {
    match t {
        ReorderTrigger::Threshold => "Threshold",
        ReorderTrigger::Predictive => "Predictive",
    }
}

fn parse_reorder_status(s: &str) -> Result<ReorderStatus, SupplyError> {
    match s {
        "PendingApproval" => Ok(ReorderStatus::PendingApproval),
        "Approved" => Ok(ReorderStatus::Approved),
        "Submitted" => Ok(ReorderStatus::Submitted),
        "Fulfilled" => Ok(ReorderStatus::Fulfilled),
        "Cancelled" => Ok(ReorderStatus::Cancelled),
        other => Err(SupplyError::Repository(sqlx::Error::Protocol(format!(
            "unknown reorder status: {other}"
        )))),
    }
}

fn reorder_status_to_str(s: &ReorderStatus) -> &'static str {
    match s {
        ReorderStatus::PendingApproval => "PendingApproval",
        ReorderStatus::Approved => "Approved",
        ReorderStatus::Submitted => "Submitted",
        ReorderStatus::Fulfilled => "Fulfilled",
        ReorderStatus::Cancelled => "Cancelled",
    }
}

#[allow(dead_code)]
fn parse_approval_level(s: &str) -> Result<ApprovalLevel, SupplyError> {
    match s {
        "Auto" => Ok(ApprovalLevel::Auto),
        "SiteAdmin" => Ok(ApprovalLevel::SiteAdmin),
        "FleetAdmin" => Ok(ApprovalLevel::FleetAdmin),
        other => Err(SupplyError::Repository(sqlx::Error::Protocol(format!(
            "unknown approval level: {other}"
        )))),
    }
}

fn approval_level_to_str(l: ApprovalLevel) -> &'static str {
    match l {
        ApprovalLevel::Auto => "Auto",
        ApprovalLevel::SiteAdmin => "SiteAdmin",
        ApprovalLevel::FleetAdmin => "FleetAdmin",
    }
}

// ---------------------------------------------------------------------------
// SupplyRepository implementation
// ---------------------------------------------------------------------------

impl SupplyRepository for PgSupplyRepository {
    async fn save_reorder(&self, request: &ReorderRequest) -> Result<(), SupplyError> {
        sqlx::query(
            "INSERT INTO supply_reorders \
             (id, printer_id, consumable_kind, current_level_pct, trigger_type, \
              status, estimated_cost_cents, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(request.id)
        .bind(request.printer_id.as_str())
        .bind(request.consumable.to_string())
        .bind(i16::from(request.current_level_pct))
        .bind(reorder_trigger_to_str(&request.trigger))
        .bind(reorder_status_to_str(&request.status))
        .bind(
            request
                .estimated_cost_cents
                .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
        )
        .bind(request.created_at)
        .execute(&self.pool)
        .await
        .map_err(SupplyError::Repository)?;

        Ok(())
    }

    async fn get_reorder(&self, id: Uuid) -> Result<ReorderRequest, SupplyError> {
        let row = sqlx::query_as::<_, ReorderRow>(
            "SELECT id, printer_id, consumable_kind, current_level_pct, trigger_type, \
             status, estimated_cost_cents, created_at, approved_at, submitted_at \
             FROM supply_reorders WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(SupplyError::Repository)?
        .ok_or(SupplyError::OrderNotFound { order_id: id })?;

        row.try_into_request()
    }

    async fn save_approval(&self, request: &ApprovalRequest) -> Result<(), SupplyError> {
        // Determine the decision string and approver EDIPI from the decision.
        let (decision_str, approver_edipi, decided_at, reason) = match &request.decision {
            Some(ApprovalDecision::Approved {
                approved_by,
                decided_at,
            }) => (
                "Approved",
                approved_by.as_str().to_string(),
                *decided_at,
                None,
            ),
            Some(ApprovalDecision::Rejected {
                rejected_by,
                decided_at,
                reason,
            }) => (
                "Rejected",
                rejected_by.as_str().to_string(),
                *decided_at,
                reason.clone(),
            ),
            None => {
                // No decision yet -- store as a pending approval with a
                // placeholder. The supply_approvals table requires a decision,
                // so we skip the insert for undecided requests.
                return Ok(());
            }
        };

        sqlx::query(
            "INSERT INTO supply_approvals \
             (id, reorder_id, approver_edipi, level, decision, reason, decided_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(request.id)
        .bind(request.reorder_id)
        .bind(&approver_edipi)
        .bind(approval_level_to_str(request.required_level))
        .bind(decision_str)
        .bind(&reason)
        .bind(decided_at)
        .execute(&self.pool)
        .await
        .map_err(SupplyError::Repository)?;

        // Also update the reorder status to match the decision.
        if decision_str == "Approved" {
            sqlx::query(
                "UPDATE supply_reorders SET status = 'Approved', approved_at = $1 WHERE id = $2",
            )
            .bind(decided_at)
            .bind(request.reorder_id)
            .execute(&self.pool)
            .await
            .map_err(SupplyError::Repository)?;
        }

        Ok(())
    }

    async fn list_pending_approvals(
        &self,
        site_filter: Option<&str>,
    ) -> Result<Vec<ApprovalRequest>, SupplyError> {
        // Pending approvals are reorders in 'PendingApproval' status that
        // do not yet have an approval record.
        let rows = if let Some(site) = site_filter {
            sqlx::query_as::<_, ReorderRow>(
                "SELECT r.id, r.printer_id, r.consumable_kind, r.current_level_pct, \
                 r.trigger_type, r.status, r.estimated_cost_cents, r.created_at, \
                 r.approved_at, r.submitted_at \
                 FROM supply_reorders r \
                 JOIN printers p ON r.printer_id = p.id \
                 WHERE r.status = 'PendingApproval' \
                   AND p.location_installation = $1 \
                 ORDER BY r.created_at ASC",
            )
            .bind(site)
            .fetch_all(&self.pool)
            .await
            .map_err(SupplyError::Repository)?
        } else {
            sqlx::query_as::<_, ReorderRow>(
                "SELECT id, printer_id, consumable_kind, current_level_pct, \
                 trigger_type, status, estimated_cost_cents, created_at, \
                 approved_at, submitted_at \
                 FROM supply_reorders \
                 WHERE status = 'PendingApproval' \
                 ORDER BY created_at ASC",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(SupplyError::Repository)?
        };

        // Convert reorder rows into `ApprovalRequest` records.
        let mut approvals = Vec::with_capacity(rows.len());
        for row in rows {
            let reorder = row.try_into_request()?;
            approvals.push(ApprovalRequest {
                id: Uuid::now_v7(),
                reorder_id: reorder.id,
                order_value_cents: reorder.estimated_cost_cents.unwrap_or(0),
                required_level: ApprovalLevel::SiteAdmin,
                created_at: reorder.created_at,
                decision: None,
            });
        }

        Ok(approvals)
    }

    async fn save_vendor_order(&self, order: &VendorOrder) -> Result<(), SupplyError> {
        // Update the reorder status to 'Submitted' and store the vendor
        // order identifier. A dedicated `vendor_orders` table would be
        // added in a future migration; for now we update the reorder row.
        sqlx::query(
            "UPDATE supply_reorders SET status = 'Submitted', submitted_at = NOW() \
             WHERE id = $1",
        )
        .bind(order.reorder_id)
        .execute(&self.pool)
        .await
        .map_err(SupplyError::Repository)?;

        Ok(())
    }

    async fn has_pending_reorder(
        &self,
        printer_id: &str,
        consumable: &str,
    ) -> Result<Option<Uuid>, SupplyError> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM supply_reorders \
             WHERE printer_id = $1 AND consumable_kind = $2 \
               AND status IN ('PendingApproval', 'Approved') \
             LIMIT 1",
        )
        .bind(printer_id)
        .bind(consumable)
        .fetch_optional(&self.pool)
        .await
        .map_err(SupplyError::Repository)?;

        Ok(row.map(|(id,)| id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumable_kind_roundtrip() {
        let kinds = [
            ConsumableKind::TonerBlack,
            ConsumableKind::TonerCyan,
            ConsumableKind::TonerMagenta,
            ConsumableKind::TonerYellow,
            ConsumableKind::Paper,
        ];
        for k in kinds {
            let s = k.to_string();
            let parsed = parse_consumable_kind(&s).unwrap();
            assert_eq!(parsed, k);
        }
    }

    #[test]
    fn reorder_status_roundtrip() {
        let statuses = [
            ReorderStatus::PendingApproval,
            ReorderStatus::Approved,
            ReorderStatus::Submitted,
            ReorderStatus::Fulfilled,
            ReorderStatus::Cancelled,
        ];
        for s in statuses {
            let str_val = reorder_status_to_str(&s);
            let parsed = parse_reorder_status(str_val).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn trigger_type_roundtrip() {
        let triggers = [ReorderTrigger::Threshold, ReorderTrigger::Predictive];
        for t in triggers {
            let str_val = reorder_trigger_to_str(&t);
            let parsed = parse_trigger_type(str_val).unwrap();
            assert_eq!(parsed, t);
        }
    }

    #[test]
    fn approval_level_roundtrip() {
        let levels = [
            ApprovalLevel::Auto,
            ApprovalLevel::SiteAdmin,
            ApprovalLevel::FleetAdmin,
        ];
        for l in levels {
            let str_val = approval_level_to_str(l);
            let parsed = parse_approval_level(str_val).unwrap();
            assert_eq!(parsed, l);
        }
    }

    #[test]
    fn reorder_row_converts_to_request() {
        let row = ReorderRow {
            id: Uuid::now_v7(),
            printer_id: "PRN-0042".to_string(),
            consumable_kind: "toner_k".to_string(),
            current_level_pct: 10,
            trigger_type: "Threshold".to_string(),
            status: "PendingApproval".to_string(),
            estimated_cost_cents: Some(5_000),
            created_at: Utc::now(),
            approved_at: None,
            submitted_at: None,
        };
        let request = row.try_into_request().unwrap();
        assert_eq!(request.current_level_pct, 10);
        assert_eq!(request.trigger, ReorderTrigger::Threshold);
        assert_eq!(request.status, ReorderStatus::PendingApproval);
    }
}
