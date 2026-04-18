// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Error types for the `pf-supply` crate.

use thiserror::Error;
use uuid::Uuid;

/// Errors returned by supply chain operations.
#[derive(Debug, Error)]
pub enum SupplyError {
    /// A supply level percentage was outside the valid 0..=100 range.
    #[error("invalid supply level {value} for {field}: must be 0..=100")]
    InvalidLevel {
        /// The field name (e.g. `"toner_k"`).
        field: String,
        /// The out-of-range value.
        value: u8,
    },

    /// Not enough historical data points to compute a prediction.
    #[error("insufficient data for prediction: need {required}, have {available}")]
    InsufficientData {
        /// Minimum data points required.
        required: usize,
        /// Data points actually available.
        available: usize,
    },

    /// A reorder was already in flight for the given printer and supply type.
    #[error(
        "duplicate reorder: printer {printer_id} already has pending order {existing_order_id}"
    )]
    DuplicateReorder {
        /// Printer with the existing order.
        printer_id: String,
        /// The existing in-flight order ID.
        existing_order_id: Uuid,
    },

    /// The approval request references an order that does not exist.
    #[error("reorder {order_id} not found")]
    OrderNotFound {
        /// The missing order ID.
        order_id: Uuid,
    },

    /// The approver lacks the required role for the order value.
    #[error("approval denied: insufficient role for order value {order_value_cents}")]
    InsufficientApprovalAuthority {
        /// Order value in cents.
        order_value_cents: u64,
    },

    /// Communication with a vendor API failed.
    #[error("vendor API error: {message}")]
    VendorApi {
        /// Sanitized error description (no secrets).
        message: String,
    },

    /// A repository (database) operation failed.
    #[error("repository error")]
    Repository(#[source] sqlx::Error),

    /// A configuration value is invalid.
    #[error("configuration error: {message}")]
    Config {
        /// Description of the configuration problem.
        message: String,
    },

    /// A common-crate validation error propagated upward.
    #[error(transparent)]
    Validation(#[from] pf_common::error::ValidationError),
}
