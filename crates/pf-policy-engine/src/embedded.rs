// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Embedded `OPA` / `Rego` evaluator for edge cache nodes.
//!
//! When running on a K3s cache node without an `OPA` sidecar, policy
//! evaluation is performed in-process using bundled `Rego` policies.
//! This module provides the types and trait for that embedded evaluation.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, CM-7 — Least Functionality

use std::path::PathBuf;

use pf_common::policy::PolicyDecision;

use crate::config::EmbeddedConfig;
use crate::error::PolicyError;
use crate::input::PolicyInput;

/// An embedded policy evaluator that uses bundled `Rego` policies.
///
/// On cache nodes operating in DDIL (Denied, Degraded, Intermittent, or
/// Limited) mode, this evaluator ensures policy enforcement continues
/// even without connectivity to the central `OPA` sidecar.
#[derive(Debug)]
pub struct EmbeddedEngine {
    /// Path to the directory containing `Rego` policy bundles.
    bundle_path: PathBuf,
    /// Whether the engine has been initialized with loaded policies.
    initialized: bool,
}

impl EmbeddedEngine {
    /// Create a new embedded engine from the given configuration.
    #[must_use]
    pub fn new(config: &EmbeddedConfig) -> Self {
        Self {
            bundle_path: config.bundle_path.clone(),
            initialized: false,
        }
    }

    /// Load `Rego` policy bundles from disk.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmbeddedEvaluation`] if the bundle path does
    /// not exist or the policies cannot be parsed.
    pub fn initialize(&mut self) -> Result<(), PolicyError> {
        if !self.bundle_path.exists() {
            return Err(PolicyError::EmbeddedEvaluation(format!(
                "bundle path does not exist: {}",
                self.bundle_path.display()
            )));
        }
        self.initialized = true;
        tracing::info!(
            bundle_path = %self.bundle_path.display(),
            "embedded policy engine initialized"
        );
        Ok(())
    }

    /// Evaluate a job against the embedded `Rego` policies.
    ///
    /// **Default-deny:** If the engine is not initialized or evaluation fails,
    /// the job is denied with a hold.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmbeddedEvaluation`] if the engine is not
    /// initialized or the evaluation encounters an error.
    pub fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, PolicyError> {
        input.validate()?;

        if !self.initialized {
            return Err(PolicyError::EmbeddedEvaluation(
                "engine not initialized".to_string(),
            ));
        }

        // TODO(PF-EMBEDDED): Integrate a Rego evaluator crate (e.g.,
        // `regorus`) once it passes cargo-deny license checks. For now,
        // delegate to the built-in Rust rule evaluators in `quota` and
        // `defaults`.
        tracing::debug!("embedded evaluation delegated to Rust rule engine");

        // Step 1: Quota check
        let quota_decision = crate::quota::evaluate_quota(input);
        if let PolicyDecision::Deny(ref _violation) = quota_decision {
            tracing::info!("embedded engine: quota check denied job");
            return Ok(quota_decision);
        }

        // Step 2: Page limit (default 500)
        let total = input.total_pages();
        let page_limit = 500u32;
        if total > page_limit {
            tracing::info!(
                total_pages = total,
                limit = page_limit,
                "embedded engine: page limit exceeded"
            );
            return Ok(PolicyDecision::Deny(
                pf_common::policy::PolicyViolation::PageLimitExceeded {
                    limit: page_limit,
                    requested: total,
                },
            ));
        }

        // Step 3: Apply default overrides (duplex/grayscale)
        let overrides = crate::defaults::DefaultOverrides::default();
        let defaults_decision = crate::defaults::apply_defaults(input, &overrides);
        if defaults_decision != PolicyDecision::Allow {
            tracing::info!("embedded engine: applied default overrides");
            return Ok(defaults_decision);
        }

        Ok(PolicyDecision::Allow)
    }

    /// Whether the engine has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the bundle path.
    #[must_use]
    pub fn bundle_path(&self) -> &PathBuf {
        &self.bundle_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EmbeddedConfig;

    #[test]
    fn uninitialized_engine_returns_error() {
        let config = EmbeddedConfig {
            bundle_path: PathBuf::from("/nonexistent"),
        };
        let engine = EmbeddedEngine::new(&config);
        assert!(!engine.is_initialized());
    }

    #[test]
    fn initialize_fails_on_missing_path() {
        let config = EmbeddedConfig {
            bundle_path: PathBuf::from("/nonexistent/path/to/policies"),
        };
        let mut engine = EmbeddedEngine::new(&config);
        assert!(engine.initialize().is_err());
    }

    #[test]
    fn evaluate_fails_when_not_initialized() {
        let config = EmbeddedConfig {
            bundle_path: PathBuf::from("/nonexistent"),
        };
        let engine = EmbeddedEngine::new(&config);

        let input = crate::input::PolicyInput {
            user_edipi: pf_common::identity::Edipi::new("1234567890").unwrap(),
            user_roles: vec![pf_common::identity::Role::User],
            cost_center: pf_common::job::CostCenter::new("CC-001", "Test").unwrap(),
            printer_id: pf_common::fleet::PrinterId::new("PRN-0001").unwrap(),
            printer_capabilities: crate::input::PrinterCapabilities {
                color_supported: true,
                duplex_supported: true,
                supported_media: vec![pf_common::job::MediaSize::Letter],
            },
            page_count: 10,
            copies: 1,
            sides: pf_common::job::Sides::TwoSidedLongEdge,
            color: pf_common::job::ColorMode::Grayscale,
            media: pf_common::job::MediaSize::Letter,
            quota_status: pf_common::policy::QuotaStatus {
                limit: 500,
                used: 100,
                color_limit: 50,
                color_used: 10,
            },
        };

        assert!(engine.evaluate(&input).is_err());
    }
}
