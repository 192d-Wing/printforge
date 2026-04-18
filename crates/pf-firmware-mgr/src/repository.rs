// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for firmware versions, deployment history, and rollback
//! records.
//!
//! Abstracts over `PostgreSQL` storage so that the firmware manager can be
//! tested with in-memory implementations.

use std::future::Future;

use uuid::Uuid;

use pf_common::fleet::PrinterModel;

use crate::approval::ApprovalRequest;
use crate::error::FirmwareError;
use crate::registry::ArtifactMetadata;
use crate::rollback::RollbackRecord;
use crate::rollout::Rollout;

/// Repository trait for firmware management persistence.
///
/// All firmware lifecycle data is stored through this trait, enabling
/// both `PostgreSQL`-backed production storage and in-memory test doubles.
pub trait FirmwareRepository: Send + Sync {
    /// Store a firmware artifact metadata record.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] if the insert fails.
    fn save_artifact(
        &self,
        metadata: &ArtifactMetadata,
    ) -> impl Future<Output = Result<(), FirmwareError>> + Send;

    /// Retrieve firmware artifact metadata by identifier.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::NotFound`] if no matching record exists, or
    /// [`FirmwareError::Database`] on query failure.
    fn get_artifact(
        &self,
        firmware_id: Uuid,
    ) -> impl Future<Output = Result<ArtifactMetadata, FirmwareError>> + Send;

    /// List all firmware artifacts for a given printer model.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] on query failure.
    fn list_artifacts_for_model(
        &self,
        model: &PrinterModel,
    ) -> impl Future<Output = Result<Vec<ArtifactMetadata>, FirmwareError>> + Send;

    /// Store a rollout record.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] if the insert fails.
    fn save_rollout(
        &self,
        rollout: &Rollout,
    ) -> impl Future<Output = Result<(), FirmwareError>> + Send;

    /// Retrieve a rollout by identifier.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::NotFound`] or [`FirmwareError::Database`].
    fn get_rollout(
        &self,
        rollout_id: Uuid,
    ) -> impl Future<Output = Result<Rollout, FirmwareError>> + Send;

    /// Update an existing rollout record.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] if the update fails.
    fn update_rollout(
        &self,
        rollout: &Rollout,
    ) -> impl Future<Output = Result<(), FirmwareError>> + Send;

    /// Store an approval request.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] if the insert fails.
    fn save_approval(
        &self,
        approval: &ApprovalRequest,
    ) -> impl Future<Output = Result<(), FirmwareError>> + Send;

    /// Retrieve an approval request by firmware identifier.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::NotFound`] or [`FirmwareError::Database`].
    fn get_approval_for_firmware(
        &self,
        firmware_id: Uuid,
    ) -> impl Future<Output = Result<ApprovalRequest, FirmwareError>> + Send;

    /// Store a rollback record.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] if the insert fails.
    fn save_rollback(
        &self,
        record: &RollbackRecord,
    ) -> impl Future<Output = Result<(), FirmwareError>> + Send;

    /// Retrieve rollback records for a given rollout.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareError::Database`] on query failure.
    fn get_rollbacks_for_rollout(
        &self,
        rollout_id: Uuid,
    ) -> impl Future<Output = Result<Vec<RollbackRecord>, FirmwareError>> + Send;
}
