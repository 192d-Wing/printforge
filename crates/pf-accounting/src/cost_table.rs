// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configurable cost tables with per-installation overrides.
//!
//! Different installations may have different supply contracts, so cost tables
//! support a global default with per-installation overrides.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::CostTableConfig;
use crate::error::AccountingError;

/// A collection of cost tables keyed by installation identifier.
///
/// Provides a global default and optional per-installation overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTableRegistry {
    /// The default cost table applied when no installation override exists.
    default_table: CostTableConfig,

    /// Per-installation cost table overrides, keyed by installation code.
    overrides: HashMap<String, CostTableConfig>,
}

impl CostTableRegistry {
    /// Create a new registry with the given default cost table.
    #[must_use]
    pub fn new(default_table: CostTableConfig) -> Self {
        Self {
            default_table,
            overrides: HashMap::new(),
        }
    }

    /// Register a cost table override for a specific installation.
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::InvalidCostValue`] if the installation code
    /// is empty.
    pub fn set_override(
        &mut self,
        installation_code: &str,
        table: CostTableConfig,
    ) -> Result<(), AccountingError> {
        let code = installation_code.trim();
        if code.is_empty() {
            return Err(AccountingError::InvalidCostValue {
                message: "installation code cannot be empty".to_string(),
            });
        }
        self.overrides.insert(code.to_string(), table);
        Ok(())
    }

    /// Remove a per-installation override, reverting to the default.
    pub fn remove_override(&mut self, installation_code: &str) {
        self.overrides.remove(installation_code.trim());
    }

    /// Resolve the cost table for a given installation.
    ///
    /// Returns the installation-specific override if one exists, otherwise
    /// the default cost table.
    #[must_use]
    pub fn resolve(&self, installation_code: &str) -> &CostTableConfig {
        self.overrides
            .get(installation_code.trim())
            .unwrap_or(&self.default_table)
    }

    /// Return a reference to the default cost table.
    #[must_use]
    pub fn default_table(&self) -> &CostTableConfig {
        &self.default_table
    }

    /// Return the number of installation-specific overrides.
    #[must_use]
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_table() -> CostTableConfig {
        CostTableConfig::default()
    }

    #[test]
    fn resolve_returns_default_when_no_override() {
        let registry = CostTableRegistry::new(default_table());
        let table = registry.resolve("JBSA");
        assert_eq!(table.base_cost_cents, default_table().base_cost_cents);
    }

    #[test]
    fn resolve_returns_override_when_present() {
        let mut registry = CostTableRegistry::new(default_table());
        let mut custom = default_table();
        custom.base_cost_cents = 5;
        registry.set_override("JBSA", custom).unwrap();

        let table = registry.resolve("JBSA");
        assert_eq!(table.base_cost_cents, 5);
    }

    #[test]
    fn remove_override_reverts_to_default() {
        let mut registry = CostTableRegistry::new(default_table());
        let mut custom = default_table();
        custom.base_cost_cents = 10;
        registry.set_override("JBSA", custom).unwrap();
        registry.remove_override("JBSA");

        let table = registry.resolve("JBSA");
        assert_eq!(table.base_cost_cents, default_table().base_cost_cents);
    }

    #[test]
    fn set_override_rejects_empty_code() {
        let mut registry = CostTableRegistry::new(default_table());
        let result = registry.set_override("", default_table());
        assert!(result.is_err());
    }
}
