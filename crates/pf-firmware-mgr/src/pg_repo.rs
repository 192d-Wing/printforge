// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`FirmwareRepository`].
//!
//! **NIST 800-53 Rev 5:** SI-2 -- Flaw Remediation, CM-3 -- Configuration Change Control
//! Persists firmware artifact metadata, rollout state, approval records,
//! and rollback history in `PostgreSQL`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use pf_common::fleet::PrinterModel;
use pf_common::identity::Edipi;

use crate::approval::{ApprovalRequest, ApprovalStatus};
use crate::error::FirmwareError;
use crate::registry::ArtifactMetadata;
use crate::repository::FirmwareRepository;
use crate::rollback::{RollbackReason, RollbackRecord};
use crate::rollout::{Rollout, RolloutPhase, RolloutStatus};
use crate::validation::ValidatedFirmware;

/// `PostgreSQL`-backed firmware repository.
///
/// **NIST 800-53 Rev 5:** SI-2, CM-3
pub struct PgFirmwareRepository {
    pool: PgPool,
}

impl PgFirmwareRepository {
    /// Create a new `PgFirmwareRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// ---------------------------------------------------------------------------
// Internal row types
// ---------------------------------------------------------------------------

/// Row returned from the `firmware_artifacts` table.
#[derive(sqlx::FromRow)]
struct ArtifactRow {
    id: Uuid,
    vendor: String,
    model: String,
    version: String,
    checksum_sha256: String,
    size_bytes: i64,
    #[allow(dead_code)]
    signature_info: serde_json::Value,
    acquired_at: DateTime<Utc>,
    #[allow(dead_code)]
    validated_at: Option<DateTime<Utc>>,
}

impl ArtifactRow {
    fn into_metadata(self) -> ArtifactMetadata {
        ArtifactMetadata {
            firmware_id: self.id,
            model: PrinterModel {
                vendor: self.vendor,
                model: self.model,
            },
            version: self.version,
            sha256: self.checksum_sha256,
            pushed_at: self.acquired_at,
            size_bytes: u64::try_from(self.size_bytes).unwrap_or(0),
        }
    }
}

/// Row returned from the `firmware_deployments` table, used to
/// reconstruct [`Rollout`] records.
#[derive(sqlx::FromRow)]
struct DeploymentRow {
    id: Uuid,
    artifact_id: Uuid,
    #[allow(dead_code)]
    printer_id: String,
    status: String,
    phase: String,
    started_at: DateTime<Utc>,
    soak_started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_rollout_status(s: &str) -> Result<RolloutStatus, FirmwareError> {
    match s {
        "Pending" => Ok(RolloutStatus::Pending),
        "InProgress" => Ok(RolloutStatus::InProgress),
        "Soaking" => Ok(RolloutStatus::Soaking),
        "Halted" => Ok(RolloutStatus::Halted),
        "Completed" => Ok(RolloutStatus::Completed),
        "RolledBack" => Ok(RolloutStatus::RolledBack),
        "Cancelled" => Ok(RolloutStatus::Cancelled),
        other => Err(FirmwareError::Database {
            source: sqlx::Error::Protocol(format!("unknown rollout status: {other}")),
        }),
    }
}

fn rollout_status_to_str(s: RolloutStatus) -> &'static str {
    match s {
        RolloutStatus::Pending => "Pending",
        RolloutStatus::InProgress => "InProgress",
        RolloutStatus::Soaking => "Soaking",
        RolloutStatus::Halted => "Halted",
        RolloutStatus::Completed => "Completed",
        RolloutStatus::RolledBack => "RolledBack",
        RolloutStatus::Cancelled => "Cancelled",
    }
}

fn parse_rollout_phase(s: &str) -> Result<RolloutPhase, FirmwareError> {
    match s {
        "Canary" => Ok(RolloutPhase::Canary),
        "Staging" => Ok(RolloutPhase::Staging),
        "Fleet" => Ok(RolloutPhase::Fleet),
        other => Err(FirmwareError::Database {
            source: sqlx::Error::Protocol(format!("unknown rollout phase: {other}")),
        }),
    }
}

fn rollout_phase_to_str(p: RolloutPhase) -> &'static str {
    match p {
        RolloutPhase::Canary => "Canary",
        RolloutPhase::Staging => "Staging",
        RolloutPhase::Fleet => "Fleet",
    }
}

fn parse_approval_status(s: &str) -> Result<ApprovalStatus, FirmwareError> {
    match s {
        "Pending" => Ok(ApprovalStatus::Pending),
        "Approved" => Ok(ApprovalStatus::Approved),
        "Rejected" => Ok(ApprovalStatus::Rejected),
        "Expired" => Ok(ApprovalStatus::Expired),
        other => Err(FirmwareError::Database {
            source: sqlx::Error::Protocol(format!("unknown approval status: {other}")),
        }),
    }
}

fn approval_status_to_str(s: ApprovalStatus) -> &'static str {
    match s {
        ApprovalStatus::Pending => "Pending",
        ApprovalStatus::Approved => "Approved",
        ApprovalStatus::Rejected => "Rejected",
        ApprovalStatus::Expired => "Expired",
    }
}

// ---------------------------------------------------------------------------
// FirmwareRepository implementation
// ---------------------------------------------------------------------------

impl FirmwareRepository for PgFirmwareRepository {
    async fn save_artifact(&self, metadata: &ArtifactMetadata) -> Result<(), FirmwareError> {
        sqlx::query(
            "INSERT INTO firmware_artifacts \
             (id, vendor, model, version, checksum_sha256, size_bytes, acquired_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(metadata.firmware_id)
        .bind(&metadata.model.vendor)
        .bind(&metadata.model.model)
        .bind(&metadata.version)
        .bind(&metadata.sha256)
        .bind(i64::try_from(metadata.size_bytes).unwrap_or(i64::MAX))
        .bind(metadata.pushed_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_artifact(&self, firmware_id: Uuid) -> Result<ArtifactMetadata, FirmwareError> {
        let row = sqlx::query_as::<_, ArtifactRow>(
            "SELECT id, vendor, model, version, checksum_sha256, size_bytes, \
             signature_info, acquired_at, validated_at \
             FROM firmware_artifacts WHERE id = $1",
        )
        .bind(firmware_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FirmwareError::NotFound { firmware_id })?;

        Ok(row.into_metadata())
    }

    async fn list_artifacts_for_model(
        &self,
        model: &PrinterModel,
    ) -> Result<Vec<ArtifactMetadata>, FirmwareError> {
        let rows = sqlx::query_as::<_, ArtifactRow>(
            "SELECT id, vendor, model, version, checksum_sha256, size_bytes, \
             signature_info, acquired_at, validated_at \
             FROM firmware_artifacts WHERE vendor = $1 AND model = $2 \
             ORDER BY acquired_at DESC",
        )
        .bind(&model.vendor)
        .bind(&model.model)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(ArtifactRow::into_metadata).collect())
    }

    async fn save_rollout(&self, rollout: &Rollout) -> Result<(), FirmwareError> {
        // Persist the rollout as a deployment record in `firmware_deployments`.
        // The full `Rollout` struct has richer data than the table schema; we
        // store the core columns and serialise auxiliary fields as JSONB if
        // needed in a future migration.
        // Look up the artifact ID by vendor/model/version so the FK
        // into `firmware_artifacts` is valid.
        let artifact_id: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM firmware_artifacts \
             WHERE vendor = $1 AND model = $2 AND version = $3 LIMIT 1",
        )
        .bind(&rollout.model.vendor)
        .bind(&rollout.model.model)
        .bind(&rollout.artifact.tag)
        .fetch_optional(&self.pool)
        .await?;

        let artifact_uuid = artifact_id
            .map(|(id,)| id)
            .ok_or_else(|| FirmwareError::NotFound {
                firmware_id: rollout.id,
            })?;

        // We store one row per rollout using the rollout ID. The printer_id
        // column uses the first phase target or a sentinel value.
        let printer_id = rollout
            .phase_targets
            .first()
            .map_or("ROLLOUT", |p| p.as_str());

        sqlx::query(
            "INSERT INTO firmware_deployments \
             (id, artifact_id, printer_id, status, phase, started_at, \
              soak_started_at, completed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(rollout.id)
        .bind(artifact_uuid)
        .bind(printer_id)
        .bind(rollout_status_to_str(rollout.status))
        .bind(rollout_phase_to_str(rollout.current_phase))
        .bind(rollout.created_at)
        .bind(rollout.soak_started_at)
        .bind(rollout.finished_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_rollout(&self, rollout_id: Uuid) -> Result<Rollout, FirmwareError> {
        let row = sqlx::query_as::<_, DeploymentRow>(
            "SELECT id, artifact_id, printer_id, status, phase, started_at, \
             soak_started_at, completed_at \
             FROM firmware_deployments WHERE id = $1",
        )
        .bind(rollout_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FirmwareError::NotFound {
            firmware_id: rollout_id,
        })?;

        // Retrieve the artifact metadata to reconstruct the `OciArtifactRef`.
        let artifact_meta = self.get_artifact(row.artifact_id).await?;

        let status = parse_rollout_status(&row.status)?;
        let phase = parse_rollout_phase(&row.phase)?;

        // Build a minimal `OciArtifactRef` from persisted artifact data.
        let artifact_ref = crate::registry::OciArtifactRef {
            registry_url: url::Url::parse("https://registry.printforge.mil")
                .expect("hardcoded URL is valid"),
            repository: format!(
                "firmware/{}/{}",
                artifact_meta.model.vendor.to_lowercase(),
                artifact_meta.model.model.to_lowercase().replace(' ', "-")
            ),
            tag: artifact_meta.version.clone(),
            digest: format!("sha256:{}", artifact_meta.sha256),
        };

        Ok(Rollout {
            id: row.id,
            artifact: artifact_ref,
            model: artifact_meta.model,
            config: crate::config::RolloutConfig::default(),
            current_phase: phase,
            status,
            phase_targets: Vec::new(),
            completed_targets: Vec::new(),
            failed_targets: Vec::new(),
            created_at: row.started_at,
            soak_started_at: row.soak_started_at,
            finished_at: row.completed_at,
        })
    }

    async fn update_rollout(&self, rollout: &Rollout) -> Result<(), FirmwareError> {
        sqlx::query(
            "UPDATE firmware_deployments SET status = $1, phase = $2, \
             soak_started_at = $3, completed_at = $4 WHERE id = $5",
        )
        .bind(rollout_status_to_str(rollout.status))
        .bind(rollout_phase_to_str(rollout.current_phase))
        .bind(rollout.soak_started_at)
        .bind(rollout.finished_at)
        .bind(rollout.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn save_approval(&self, approval: &ApprovalRequest) -> Result<(), FirmwareError> {
        // Store approval records alongside the firmware artifacts table.
        // A dedicated `firmware_approvals` table would be preferable in a
        // future migration; for now we serialise to a JSONB sidecar or use
        // a lightweight insert into a denormalised approvals table.
        //
        // We use the `firmware_artifacts` table's `signature_info` JSONB column
        // as a pragmatic storage location until a dedicated table is created.
        let approval_json = serde_json::json!({
            "approval_id": approval.id,
            "status": approval_status_to_str(approval.status),
            "requested_by": approval.requested_by.as_str(),
            "requested_at": approval.requested_at,
            "reviewed_by": approval.reviewed_by.as_ref().map(Edipi::as_str),
            "reviewed_at": approval.reviewed_at,
            "review_notes": approval.review_notes,
            "version": approval.version,
        });

        sqlx::query("UPDATE firmware_artifacts SET signature_info = $1 WHERE id = $2")
            .bind(&approval_json)
            .bind(approval.firmware.firmware_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_approval_for_firmware(
        &self,
        firmware_id: Uuid,
    ) -> Result<ApprovalRequest, FirmwareError> {
        let row = sqlx::query_as::<_, ArtifactRow>(
            "SELECT id, vendor, model, version, checksum_sha256, size_bytes, \
             signature_info, acquired_at, validated_at \
             FROM firmware_artifacts WHERE id = $1",
        )
        .bind(firmware_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FirmwareError::NotFound { firmware_id })?;

        // Parse the approval data from the `signature_info` JSONB column.
        let info = &row.signature_info;

        let approval_id: Uuid = info
            .get("approval_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .ok_or(FirmwareError::NotFound { firmware_id })?;

        let status_str = info
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Pending");

        let status = parse_approval_status(status_str)?;

        let requested_by_str = info
            .get("requested_by")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("0000000000");

        let requested_by = Edipi::new(requested_by_str).map_err(|_| FirmwareError::Database {
            source: sqlx::Error::Protocol(format!(
                "invalid EDIPI in approval record: {requested_by_str}"
            )),
        })?;

        let requested_at: DateTime<Utc> = info
            .get("requested_at")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(Utc::now);

        let reviewed_by = info
            .get("reviewed_by")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Edipi::new(s).ok());

        let reviewed_at: Option<DateTime<Utc>> = info
            .get("reviewed_at")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse().ok());

        let review_notes = info
            .get("review_notes")
            .and_then(serde_json::Value::as_str)
            .map(String::from);

        let version = info
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&row.version)
            .to_string();

        let validated_firmware = ValidatedFirmware {
            firmware_id,
            computed_sha256: row.checksum_sha256.clone(),
            signature_verified: status == ApprovalStatus::Approved,
            validated_at: row.validated_at.unwrap_or_else(Utc::now),
        };

        Ok(ApprovalRequest {
            id: approval_id,
            firmware: validated_firmware,
            model: PrinterModel {
                vendor: row.vendor,
                model: row.model,
            },
            version,
            status,
            requested_by,
            requested_at,
            reviewed_by,
            reviewed_at,
            review_notes,
        })
    }

    async fn save_rollback(&self, record: &RollbackRecord) -> Result<(), FirmwareError> {
        // Store rollback records as deployment rows with 'RolledBack' status
        // and the rollback metadata serialised as JSONB in the deployment record.
        let reason_json = serde_json::to_value(&record.reason).unwrap_or_default();
        let printer_statuses_json =
            serde_json::to_value(&record.printer_statuses).unwrap_or_default();

        let rollback_json = serde_json::json!({
            "rollback_id": record.id,
            "rollout_id": record.rollout_id,
            "triggered_at_phase": rollout_phase_to_str(record.triggered_at_phase),
            "reason": reason_json,
            "printer_statuses": printer_statuses_json,
            "initiated_at": record.initiated_at,
            "completed_at": record.completed_at,
            "from_tag": record.from_artifact.tag,
            "to_tag": record.to_artifact.tag,
        });

        sqlx::query(
            "INSERT INTO firmware_deployments \
             (id, artifact_id, printer_id, status, phase, started_at, \
              soak_started_at, completed_at) \
             VALUES ($1, $2, $3, 'RolledBack', $4, $5, NULL, $6)",
        )
        .bind(record.id)
        .bind(record.rollout_id)
        .bind(
            serde_json::to_string(&rollback_json)
                .unwrap_or_default()
                .get(..255)
                .unwrap_or("ROLLBACK"),
        )
        .bind(rollout_phase_to_str(record.triggered_at_phase))
        .bind(record.initiated_at)
        .bind(record.completed_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_rollbacks_for_rollout(
        &self,
        rollout_id: Uuid,
    ) -> Result<Vec<RollbackRecord>, FirmwareError> {
        let rows = sqlx::query_as::<_, DeploymentRow>(
            "SELECT id, artifact_id, printer_id, status, phase, started_at, \
             soak_started_at, completed_at \
             FROM firmware_deployments \
             WHERE artifact_id = $1 AND status = 'RolledBack' \
             ORDER BY started_at DESC",
        )
        .bind(rollout_id)
        .fetch_all(&self.pool)
        .await?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let phase = parse_rollout_phase(&row.phase)?;

            // Build minimal artifact references. In a production system these
            // would be fully resolved from a dedicated rollback table.
            let placeholder_ref = crate::registry::OciArtifactRef {
                registry_url: url::Url::parse("https://registry.printforge.mil")
                    .expect("hardcoded URL is valid"),
                repository: String::new(),
                tag: String::new(),
                digest: String::new(),
            };

            records.push(RollbackRecord {
                id: row.id,
                rollout_id,
                from_artifact: placeholder_ref.clone(),
                to_artifact: placeholder_ref,
                triggered_at_phase: phase,
                reason: RollbackReason::ManualRequest {
                    requested_by: "unknown".to_string(),
                    justification: "loaded from database".to_string(),
                },
                printer_statuses: Vec::new(),
                initiated_at: row.started_at,
                completed_at: row.completed_at,
            });
        }

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_status_roundtrip() {
        let statuses = [
            RolloutStatus::Pending,
            RolloutStatus::InProgress,
            RolloutStatus::Soaking,
            RolloutStatus::Halted,
            RolloutStatus::Completed,
            RolloutStatus::RolledBack,
            RolloutStatus::Cancelled,
        ];
        for s in statuses {
            let str_val = rollout_status_to_str(s);
            let parsed = parse_rollout_status(str_val).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn rollout_phase_roundtrip() {
        let phases = [
            RolloutPhase::Canary,
            RolloutPhase::Staging,
            RolloutPhase::Fleet,
        ];
        for p in phases {
            let str_val = rollout_phase_to_str(p);
            let parsed = parse_rollout_phase(str_val).unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn approval_status_roundtrip() {
        let statuses = [
            ApprovalStatus::Pending,
            ApprovalStatus::Approved,
            ApprovalStatus::Rejected,
            ApprovalStatus::Expired,
        ];
        for s in statuses {
            let str_val = approval_status_to_str(s);
            let parsed = parse_approval_status(str_val).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn artifact_row_converts_to_metadata() {
        let row = ArtifactRow {
            id: Uuid::new_v4(),
            vendor: "HP".to_string(),
            model: "LaserJet M612".to_string(),
            version: "4.11.2.1".to_string(),
            checksum_sha256: "abcdef".to_string(),
            size_bytes: 1_048_576,
            signature_info: serde_json::json!({}),
            acquired_at: Utc::now(),
            validated_at: Some(Utc::now()),
        };
        let meta = row.into_metadata();
        assert_eq!(meta.model.vendor, "HP");
        assert_eq!(meta.size_bytes, 1_048_576);
    }
}
