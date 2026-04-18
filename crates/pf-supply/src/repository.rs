// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for supply chain persistence.
//!
//! Abstracts database access for reorder history, approval records,
//! and vendor order tracking. Implementations use `sqlx` against
//! `PostgreSQL`.
//!
//! **NIST 800-53 Rev 5:** AU-9 — Protection of Audit Information
//! (reorder history is CUI, scoped by role).

use uuid::Uuid;

use crate::approval::ApprovalRequest;
use crate::error::SupplyError;
use crate::reorder::ReorderRequest;
use crate::vendor::VendorOrder;

/// Repository trait for supply chain data persistence.
///
/// All methods return [`SupplyError::Repository`] on database failures.
pub trait SupplyRepository: Send + Sync {
    /// Persist a new reorder request.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::Repository`] on database failure.
    fn save_reorder(
        &self,
        request: &ReorderRequest,
    ) -> impl std::future::Future<Output = Result<(), SupplyError>> + Send;

    /// Retrieve a reorder request by ID.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::OrderNotFound`] if no matching record exists,
    /// or [`SupplyError::Repository`] on database failure.
    fn get_reorder(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<ReorderRequest, SupplyError>> + Send;

    /// Persist an approval request.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::Repository`] on database failure.
    fn save_approval(
        &self,
        request: &ApprovalRequest,
    ) -> impl std::future::Future<Output = Result<(), SupplyError>> + Send;

    /// Retrieve pending approval requests (optionally filtered by site).
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::Repository`] on database failure.
    fn list_pending_approvals(
        &self,
        site_filter: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<ApprovalRequest>, SupplyError>> + Send;

    /// Record a vendor order after submission.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::Repository`] on database failure.
    fn save_vendor_order(
        &self,
        order: &VendorOrder,
    ) -> impl std::future::Future<Output = Result<(), SupplyError>> + Send;

    /// Check if a pending reorder already exists for the given printer
    /// and consumable type.
    ///
    /// # Errors
    ///
    /// Returns [`SupplyError::Repository`] on database failure.
    fn has_pending_reorder(
        &self,
        printer_id: &str,
        consumable: &str,
    ) -> impl std::future::Future<Output = Result<Option<Uuid>, SupplyError>> + Send;
}
