// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `PostgreSQL` implementation of [`JobRepository`].
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! Job state transitions are recorded but never retroactively modified.
//! Status updates overwrite the current status column; the audit trail
//! is maintained separately in `pf-audit`.

use chrono::Utc;
use pf_common::identity::Edipi;
use pf_common::job::{
    ColorMode, CostCenter, JobId, JobMetadata, JobStatus, MediaSize, PrintOptions, Sides,
};
use sqlx::PgPool;

use crate::error::JobQueueError;
use crate::repository::JobRepository;
use crate::retention::RetentionQuery;
use crate::service::AdminJobSummary;

/// `PostgreSQL`-backed job metadata repository.
pub struct PgJobRepository {
    pool: PgPool,
}

impl PgJobRepository {
    /// Create a new `PgJobRepository` backed by the given connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Internal row type for the `jobs` table.
#[derive(sqlx::FromRow)]
struct JobRow {
    id: uuid::Uuid,
    owner_edipi: String,
    document_name: String,
    status: String,
    copies: i32,
    sides: String,
    color_mode: String,
    media_size: String,
    cost_center_code: String,
    cost_center_name: String,
    page_count: Option<i32>,
    submitted_at: chrono::DateTime<chrono::Utc>,
    released_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl JobRow {
    fn try_into_job(self) -> Result<JobMetadata, JobQueueError> {
        let id = JobId::new(self.id).map_err(JobQueueError::Validation)?;
        let owner = Edipi::new(&self.owner_edipi).map_err(JobQueueError::Validation)?;

        let status = parse_job_status(&self.status)?;
        let sides = parse_sides(&self.sides)?;
        let color = parse_color_mode(&self.color_mode)?;
        let media = parse_media_size(&self.media_size)?;

        let cost_center = CostCenter::new(&self.cost_center_code, &self.cost_center_name)
            .map_err(JobQueueError::Validation)?;

        Ok(JobMetadata {
            id,
            owner,
            document_name: self.document_name,
            status,
            options: PrintOptions {
                copies: u16::try_from(self.copies).unwrap_or(1),
                sides,
                color,
                media,
            },
            cost_center,
            page_count: self.page_count.map(|p| u32::try_from(p).unwrap_or(0)),
            submitted_at: self.submitted_at,
            released_at: self.released_at,
            completed_at: self.completed_at,
        })
    }
}

fn status_to_str(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Held => "Held",
        JobStatus::Waiting => "Waiting",
        JobStatus::Releasing => "Releasing",
        JobStatus::Printing => "Printing",
        JobStatus::Completed => "Completed",
        JobStatus::Failed => "Failed",
        JobStatus::Purged => "Purged",
    }
}

fn parse_job_status(s: &str) -> Result<JobStatus, JobQueueError> {
    match s {
        "Held" => Ok(JobStatus::Held),
        "Waiting" => Ok(JobStatus::Waiting),
        "Releasing" => Ok(JobStatus::Releasing),
        "Printing" => Ok(JobStatus::Printing),
        "Completed" => Ok(JobStatus::Completed),
        "Failed" => Ok(JobStatus::Failed),
        "Purged" => Ok(JobStatus::Purged),
        other => Err(JobQueueError::Internal(
            format!("unknown job status: {other}").into(),
        )),
    }
}

fn parse_sides(s: &str) -> Result<Sides, JobQueueError> {
    match s {
        "OneSided" => Ok(Sides::OneSided),
        "TwoSidedLongEdge" => Ok(Sides::TwoSidedLongEdge),
        "TwoSidedShortEdge" => Ok(Sides::TwoSidedShortEdge),
        other => Err(JobQueueError::Internal(
            format!("unknown sides: {other}").into(),
        )),
    }
}

fn parse_color_mode(s: &str) -> Result<ColorMode, JobQueueError> {
    match s {
        "Color" => Ok(ColorMode::Color),
        "Grayscale" => Ok(ColorMode::Grayscale),
        "AutoDetect" => Ok(ColorMode::AutoDetect),
        other => Err(JobQueueError::Internal(
            format!("unknown color mode: {other}").into(),
        )),
    }
}

fn parse_media_size(s: &str) -> Result<MediaSize, JobQueueError> {
    match s {
        "Letter" => Ok(MediaSize::Letter),
        "Legal" => Ok(MediaSize::Legal),
        "Ledger" => Ok(MediaSize::Ledger),
        "A4" => Ok(MediaSize::A4),
        "A3" => Ok(MediaSize::A3),
        other => Err(JobQueueError::Internal(
            format!("unknown media size: {other}").into(),
        )),
    }
}

fn sides_to_str(sides: Sides) -> &'static str {
    match sides {
        Sides::OneSided => "OneSided",
        Sides::TwoSidedLongEdge => "TwoSidedLongEdge",
        Sides::TwoSidedShortEdge => "TwoSidedShortEdge",
    }
}

fn color_mode_to_str(color: ColorMode) -> &'static str {
    match color {
        ColorMode::Color => "Color",
        ColorMode::Grayscale => "Grayscale",
        ColorMode::AutoDetect => "AutoDetect",
    }
}

fn media_size_to_str(media: MediaSize) -> &'static str {
    match media {
        MediaSize::Letter => "Letter",
        MediaSize::Legal => "Legal",
        MediaSize::Ledger => "Ledger",
        MediaSize::A4 => "A4",
        MediaSize::A3 => "A3",
    }
}

impl JobRepository for PgJobRepository {
    async fn insert(&self, job: &JobMetadata) -> Result<(), JobQueueError> {
        sqlx::query(
            "INSERT INTO jobs (id, owner_edipi, document_name, status, copies, sides, \
             color_mode, media_size, cost_center_code, cost_center_name, page_count, \
             submitted_at, released_at, completed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(job.id.as_uuid())
        .bind(job.owner.as_str())
        .bind(&job.document_name)
        .bind(status_to_str(job.status))
        .bind(i32::from(job.options.copies))
        .bind(sides_to_str(job.options.sides))
        .bind(color_mode_to_str(job.options.color))
        .bind(media_size_to_str(job.options.media))
        .bind(&job.cost_center.code)
        .bind(&job.cost_center.name)
        .bind(job.page_count.map(|p| i32::try_from(p).unwrap_or(i32::MAX)))
        .bind(job.submitted_at)
        .bind(job.released_at)
        .bind(job.completed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

        Ok(())
    }

    async fn get_by_id(&self, id: &JobId) -> Result<JobMetadata, JobQueueError> {
        let row = sqlx::query_as::<_, JobRow>(
            "SELECT id, owner_edipi, document_name, status, copies, sides, color_mode, \
             media_size, cost_center_code, cost_center_name, page_count, submitted_at, \
             released_at, completed_at FROM jobs WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?
        .ok_or(JobQueueError::NotFound)?;

        row.try_into_job()
    }

    async fn list_by_owner(&self, owner: &Edipi) -> Result<Vec<JobMetadata>, JobQueueError> {
        let rows = sqlx::query_as::<_, JobRow>(
            "SELECT id, owner_edipi, document_name, status, copies, sides, color_mode, \
             media_size, cost_center_code, cost_center_name, page_count, submitted_at, \
             released_at, completed_at FROM jobs WHERE owner_edipi = $1 ORDER BY submitted_at DESC",
        )
        .bind(owner.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

        rows.into_iter().map(JobRow::try_into_job).collect()
    }

    async fn list_by_status(&self, status: JobStatus) -> Result<Vec<JobMetadata>, JobQueueError> {
        let rows = sqlx::query_as::<_, JobRow>(
            "SELECT id, owner_edipi, document_name, status, copies, sides, color_mode, \
             media_size, cost_center_code, cost_center_name, page_count, submitted_at, \
             released_at, completed_at FROM jobs WHERE status = $1 ORDER BY submitted_at DESC",
        )
        .bind(status_to_str(status))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

        rows.into_iter().map(JobRow::try_into_job).collect()
    }

    async fn update_status(&self, id: &JobId, new_status: JobStatus) -> Result<(), JobQueueError> {
        // If transitioning to a terminal state, set completed_at.
        let completed_at = match new_status {
            JobStatus::Completed | JobStatus::Failed => Some(Utc::now()),
            _ => None,
        };

        // If transitioning to Releasing/Waiting, set released_at.
        let released_at = match new_status {
            JobStatus::Waiting | JobStatus::Releasing => Some(Utc::now()),
            _ => None,
        };

        let rows_affected = sqlx::query(
            "UPDATE jobs SET status = $1, \
             completed_at = COALESCE($2, completed_at), \
             released_at = COALESCE($3, released_at) \
             WHERE id = $4",
        )
        .bind(status_to_str(new_status))
        .bind(completed_at)
        .bind(released_at)
        .bind(id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?
        .rows_affected();

        if rows_affected == 0 {
            return Err(JobQueueError::NotFound);
        }

        Ok(())
    }

    async fn find_purgeable(
        &self,
        query: &RetentionQuery,
    ) -> Result<Vec<JobMetadata>, JobQueueError> {
        let cutoff = Utc::now()
            - chrono::Duration::from_std(query.retention_ttl).map_err(|e| {
                JobQueueError::Internal(format!("invalid retention TTL: {e}").into())
            })?;

        let rows = sqlx::query_as::<_, JobRow>(
            "SELECT id, owner_edipi, document_name, status, copies, sides, color_mode, \
             media_size, cost_center_code, cost_center_name, page_count, submitted_at, \
             released_at, completed_at FROM jobs \
             WHERE status IN ('Completed', 'Failed') \
             AND COALESCE(completed_at, submitted_at) < $1 \
             ORDER BY submitted_at LIMIT $2",
        )
        .bind(cutoff)
        .bind(i64::from(query.batch_size))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

        rows.into_iter().map(JobRow::try_into_job).collect()
    }

    async fn mark_purged(&self, ids: &[JobId]) -> Result<u64, JobQueueError> {
        if ids.is_empty() {
            return Ok(0);
        }

        let uuids: Vec<uuid::Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();

        let result = sqlx::query(
            "UPDATE jobs SET status = 'Purged' WHERE id = ANY($1) AND status != 'Purged'",
        )
        .bind(&uuids)
        .execute(&self.pool)
        .await
        .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

        Ok(result.rows_affected())
    }

    async fn list_admin_scoped(
        &self,
        installations: &[String],
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<AdminJobSummary>, u64), JobQueueError> {
        // Two branches keep each path index-friendly. Without a site filter,
        // only `idx_jobs_submitted_at` is consulted. With one, the planner
        // can use `idx_users_site_id` and loop over the matching edipis.
        let base_select = "SELECT j.id, j.owner_edipi, j.document_name, j.status, j.copies, \
             j.sides, j.color_mode, j.media_size, j.cost_center_code, j.cost_center_name, \
             j.page_count, j.submitted_at, j.released_at, j.completed_at, \
             COALESCE(u.display_name, '') AS owner_display_name, \
             COALESCE(u.site_id, '') AS owner_site_id \
             FROM jobs j LEFT JOIN users u ON j.owner_edipi = u.edipi";

        let (page, total) = if installations.is_empty() {
            let rows = sqlx::query_as::<_, AdminJobRow>(&format!(
                "{base_select} ORDER BY j.submitted_at DESC LIMIT $1 OFFSET $2"
            ))
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

            let total: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM jobs")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

            (rows, total)
        } else {
            let rows = sqlx::query_as::<_, AdminJobRow>(&format!(
                "{base_select} WHERE u.site_id = ANY($1) \
                 ORDER BY j.submitted_at DESC LIMIT $2 OFFSET $3"
            ))
            .bind(installations.to_vec())
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

            let total: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM jobs j \
                 LEFT JOIN users u ON j.owner_edipi = u.edipi \
                 WHERE u.site_id = ANY($1)",
            )
            .bind(installations.to_vec())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| JobQueueError::Repository(Box::new(e)))?;

            (rows, total)
        };

        let summaries = page
            .into_iter()
            .map(AdminJobRow::try_into_admin_summary)
            .collect::<Result<Vec<_>, _>>()?;

        Ok((summaries, u64::try_from(total).unwrap_or(0)))
    }
}

/// Internal row type for [`list_admin_scoped`]. Carries everything the
/// job row has plus the joined owner columns.
#[derive(sqlx::FromRow)]
struct AdminJobRow {
    id: uuid::Uuid,
    owner_edipi: String,
    document_name: String,
    status: String,
    copies: i32,
    sides: String,
    color_mode: String,
    media_size: String,
    cost_center_code: String,
    cost_center_name: String,
    page_count: Option<i32>,
    submitted_at: chrono::DateTime<chrono::Utc>,
    released_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    owner_display_name: String,
    owner_site_id: String,
}

impl AdminJobRow {
    fn try_into_admin_summary(self) -> Result<AdminJobSummary, JobQueueError> {
        let job = JobRow {
            id: self.id,
            owner_edipi: self.owner_edipi,
            document_name: self.document_name,
            status: self.status,
            copies: self.copies,
            sides: self.sides,
            color_mode: self.color_mode,
            media_size: self.media_size,
            cost_center_code: self.cost_center_code,
            cost_center_name: self.cost_center_name,
            page_count: self.page_count,
            submitted_at: self.submitted_at,
            released_at: self.released_at,
            completed_at: self.completed_at,
        }
        .try_into_job()?;

        Ok(AdminJobSummary {
            job,
            owner_display_name: self.owner_display_name,
            owner_site_id: self.owner_site_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_roundtrip() {
        let statuses = [
            JobStatus::Held,
            JobStatus::Waiting,
            JobStatus::Releasing,
            JobStatus::Printing,
            JobStatus::Completed,
            JobStatus::Failed,
            JobStatus::Purged,
        ];
        for status in statuses {
            let s = status_to_str(status);
            let parsed = parse_job_status(s).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn sides_roundtrip() {
        let sides = [
            Sides::OneSided,
            Sides::TwoSidedLongEdge,
            Sides::TwoSidedShortEdge,
        ];
        for s in sides {
            let str_val = sides_to_str(s);
            let parsed = parse_sides(str_val).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn color_mode_roundtrip() {
        let modes = [
            ColorMode::Color,
            ColorMode::Grayscale,
            ColorMode::AutoDetect,
        ];
        for m in modes {
            let str_val = color_mode_to_str(m);
            let parsed = parse_color_mode(str_val).unwrap();
            assert_eq!(parsed, m);
        }
    }

    #[test]
    fn media_size_roundtrip() {
        let sizes = [
            MediaSize::Letter,
            MediaSize::Legal,
            MediaSize::Ledger,
            MediaSize::A4,
            MediaSize::A3,
        ];
        for s in sizes {
            let str_val = media_size_to_str(s);
            let parsed = parse_media_size(str_val).unwrap();
            assert_eq!(parsed, s);
        }
    }
}
