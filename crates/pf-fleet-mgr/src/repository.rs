// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Repository trait for printer inventory persistence.
//!
//! Defines the storage interface for printer records. The primary implementation
//! uses `PostgreSQL` via `sqlx`, but the trait enables alternative backends
//! (in-memory for testing, `SQLite` for edge cache nodes, etc.).

use std::future::Future;

use pf_common::fleet::PrinterId;

use crate::error::FleetError;
use crate::inventory::{
    FleetSummary, PrinterQuery, PrinterRecord, PrinterStatusCounts, PrinterUpdate,
};

/// Trait for printer inventory persistence operations.
///
/// All operations are async and return [`FleetError`] on failure.
///
/// **NIST 800-53 Rev 5:** CM-8 — System Component Inventory
pub trait PrinterRepository: Send + Sync {
    /// Insert a new printer record into the inventory.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::Repository`] on database failure.
    /// Returns [`FleetError::Validation`] if the printer ID already exists.
    fn insert(&self, record: &PrinterRecord)
    -> impl Future<Output = Result<(), FleetError>> + Send;

    /// Retrieve a printer record by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::PrinterNotFound`] if no printer with the given ID exists.
    /// Returns [`FleetError::Repository`] on database failure.
    fn get_by_id(
        &self,
        id: &PrinterId,
    ) -> impl Future<Output = Result<PrinterRecord, FleetError>> + Send;

    /// Update selected fields on an existing printer record.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::PrinterNotFound`] if no printer with the given ID exists.
    /// Returns [`FleetError::Repository`] on database failure.
    fn update(
        &self,
        id: &PrinterId,
        update: &PrinterUpdate,
    ) -> impl Future<Output = Result<(), FleetError>> + Send;

    /// Remove a printer from the inventory.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::PrinterNotFound`] if no printer with the given ID exists.
    /// Returns [`FleetError::Repository`] on database failure.
    fn delete(&self, id: &PrinterId) -> impl Future<Output = Result<(), FleetError>> + Send;

    /// Query the printer inventory with filters and pagination.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::Repository`] on database failure.
    fn query(
        &self,
        query: &PrinterQuery,
    ) -> impl Future<Output = Result<Vec<PrinterRecord>, FleetError>> + Send;

    /// Get fleet summary statistics for the dashboard.
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::Repository`] on database failure.
    fn summary(&self) -> impl Future<Output = Result<FleetSummary, FleetError>> + Send;

    /// Count printers by operational status, optionally scoped to a set of
    /// installations. An empty `installations` slice means "no installation
    /// filter" (count across the entire fleet).
    ///
    /// **NIST 800-53 Rev 5:** AC-3 — Access Enforcement
    /// (Callers that hold a per-site scope MUST pass only their authorized
    /// installations.)
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::Repository`] on database failure.
    fn count_by_status(
        &self,
        installations: &[String],
    ) -> impl Future<Output = Result<PrinterStatusCounts, FleetError>> + Send;

    /// List all printer IDs in the inventory (for polling scheduler).
    ///
    /// # Errors
    ///
    /// Returns [`FleetError::Repository`] on database failure.
    fn list_ids(&self) -> impl Future<Output = Result<Vec<PrinterId>, FleetError>> + Send;
}

#[cfg(test)]
mod tests {
    // Repository trait tests require a mock or in-memory implementation.
    // Integration tests against a real database live in tests/integration/.
}
