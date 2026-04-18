// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Print job types: `JobId`, `JobMetadata`, `JobStatus`, `PrintOptions`, `CostCenter`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ValidationError;
use crate::fleet::PrinterId;
use crate::identity::Edipi;

/// A time-ordered job identifier (`UUIDv7`).
///
/// **NIST 800-53 Rev 5:** SI-10 — validated on construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(Uuid);

impl JobId {
    /// Create a new `JobId` from a UUID, validating it is a v7 UUID.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidJobId` if the UUID is not version 7.
    pub fn new(id: Uuid) -> Result<Self, ValidationError> {
        if id.get_version_num() != 7 {
            return Err(ValidationError::InvalidJobId(format!(
                "expected `UUIDv7`, got version {}",
                id.get_version_num()
            )));
        }
        Ok(Self(id))
    }

    /// Generate a fresh `UUIDv7` job identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }

    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

/// The lifecycle state of a print job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job accepted and held (Follow-Me: awaiting release at a printer).
    Held,
    /// Job released by user, waiting for printer availability.
    Waiting,
    /// Job being sent to the target printer.
    Releasing,
    /// Printer is actively printing the job.
    Printing,
    /// Job printed successfully.
    Completed,
    /// Job failed during release or printing.
    Failed,
    /// Job data purged after retention period.
    Purged,
}

/// Duplex / simplex selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sides {
    OneSided,
    TwoSidedLongEdge,
    TwoSidedShortEdge,
}

/// Color mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColorMode {
    Color,
    Grayscale,
    AutoDetect,
}

/// Standard media sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaSize {
    Letter,
    Legal,
    Ledger,
    A4,
    A3,
}

/// User-selected (or default) print options attached to a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintOptions {
    pub copies: u16,
    pub sides: Sides,
    pub color: ColorMode,
    pub media: MediaSize,
}

impl Default for PrintOptions {
    fn default() -> Self {
        Self {
            copies: 1,
            sides: Sides::TwoSidedLongEdge,
            color: ColorMode::Grayscale,
            media: MediaSize::Letter,
        }
    }
}

/// An organizational cost center for chargeback.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CostCenter {
    pub code: String,
    pub name: String,
}

impl CostCenter {
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidCostCenter` if the code is empty.
    pub fn new(code: &str, name: &str) -> Result<Self, ValidationError> {
        let code = code.trim();
        if code.is_empty() {
            return Err(ValidationError::InvalidCostCenter(
                "code cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            code: code.to_string(),
            name: name.trim().to_string(),
        })
    }
}

/// Full metadata for a print job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMetadata {
    pub id: JobId,
    pub owner: Edipi,
    pub document_name: String,
    pub status: JobStatus,
    pub options: PrintOptions,
    pub cost_center: CostCenter,
    pub page_count: Option<u32>,
    /// Printer the job was released to, if any. Set at the
    /// Held -> Waiting transition by the release path. `None` while the
    /// job is still Held or if it ended without being routed.
    #[serde(default)]
    pub target_printer: Option<PrinterId>,
    pub submitted_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_id_generate_is_v7() {
        let id = JobId::generate();
        assert_eq!(id.as_uuid().get_version_num(), 7);
    }

    #[test]
    fn nist_si10_job_id_rejects_v4() {
        let v4 = Uuid::new_v4();
        assert!(JobId::new(v4).is_err());
    }

    #[test]
    fn cost_center_rejects_empty_code() {
        assert!(CostCenter::new("", "Test").is_err());
        assert!(CostCenter::new("   ", "Test").is_err());
    }

    #[test]
    fn default_print_options_are_duplex_grayscale() {
        let opts = PrintOptions::default();
        assert_eq!(opts.copies, 1);
        assert_eq!(opts.sides, Sides::TwoSidedLongEdge);
        assert_eq!(opts.color, ColorMode::Grayscale);
    }
}
