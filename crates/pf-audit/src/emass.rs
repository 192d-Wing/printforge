// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `eMASS` artifact generation for RMF (Risk Management Framework) controls.
//!
//! Generates evidence documents formatted for `eMASS` import, grouped by
//! NIST 800-53 Rev 5 control family (AC, AU, IA, SC, SI).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single `eMASS` evidence artifact for a NIST 800-53 control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmassArtifact {
    /// NIST 800-53 Rev 5 control identifier (e.g., "AU-2").
    pub control_id: String,

    /// Control family (e.g., "AU", "AC", "IA").
    pub control_family: String,

    /// Human-readable implementation description.
    pub implementation_description: String,

    /// How the control is assessed (test procedure summary).
    pub assessment_procedure: String,

    /// Artifact type (e.g., "System Log", "Configuration", "Test Result").
    pub artifact_type: ArtifactType,

    /// When this evidence was generated.
    pub generated_at: DateTime<Utc>,

    /// The system name for `eMASS` registration.
    pub system_name: String,
}

/// Types of `eMASS` artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    /// System or application log evidence.
    SystemLog,
    /// Configuration file or setting evidence.
    Configuration,
    /// Automated test result evidence.
    TestResult,
    /// Screenshot or manual verification evidence.
    Screenshot,
    /// Policy or procedure document reference.
    PolicyDocument,
}

/// Builder for generating `eMASS` artifacts for a set of controls.
///
/// Groups artifacts by control family for bulk `eMASS` import.
#[derive(Debug, Default)]
pub struct EmassArtifactBuilder {
    system_name: String,
    artifacts: Vec<EmassArtifact>,
}

impl EmassArtifactBuilder {
    /// Create a new builder for the given system name.
    #[must_use]
    pub fn new(system_name: &str) -> Self {
        Self {
            system_name: system_name.to_string(),
            artifacts: Vec::new(),
        }
    }

    /// Add an artifact for the given NIST control.
    #[must_use]
    pub fn add_artifact(
        mut self,
        control_id: &str,
        implementation: &str,
        assessment: &str,
        artifact_type: ArtifactType,
    ) -> Self {
        let family = control_id.split('-').next().unwrap_or("XX").to_string();

        self.artifacts.push(EmassArtifact {
            control_id: control_id.to_string(),
            control_family: family,
            implementation_description: implementation.to_string(),
            assessment_procedure: assessment.to_string(),
            artifact_type,
            generated_at: Utc::now(),
            system_name: self.system_name.clone(),
        });
        self
    }

    /// Build the complete list of artifacts, sorted by control family then ID.
    #[must_use]
    pub fn build(mut self) -> Vec<EmassArtifact> {
        self.artifacts.sort_by(|a, b| {
            a.control_family
                .cmp(&b.control_family)
                .then_with(|| a.control_id.cmp(&b.control_id))
        });
        self.artifacts
    }

    /// Generate the standard `PrintForge` AU-family artifacts.
    ///
    /// Covers AU-2 (Event Logging), AU-3 (Content), AU-6 (Review),
    /// AU-9 (Protection), AU-12 (Generation).
    #[must_use]
    pub fn with_au_family(self) -> Self {
        self.add_artifact(
            "AU-2",
            "PrintForge defines a comprehensive event catalog in pf-common::audit::EventKind \
             covering authentication, job lifecycle, fleet operations, firmware management, \
             policy enforcement, and administrative actions.",
            "Review event_catalog.rs for complete EventKind-to-NIST mapping. Run \
             nist_au2_every_event_kind_has_control_mapping test.",
            ArtifactType::TestResult,
        )
        .add_artifact(
            "AU-3",
            "Every AuditEvent contains: who (actor EDIPI), what (EventKind), when (UTC \
             timestamp), where (source IP), and outcome (Success/Failure). Schema is \
             validated by the collector before persistence.",
            "Review pf-common::audit::AuditEvent struct. Run nist_au3_* tests in \
             collector module.",
            ArtifactType::TestResult,
        )
        .add_artifact(
            "AU-6",
            "Audit events are exported in CEF format to the configured SIEM (Splunk/Elastic) \
             via TLS. The query API enables compliance personnel to search and filter events.",
            "Review siem_export.rs CEF formatter. Run nist_au6_* tests.",
            ArtifactType::SystemLog,
        )
        .add_artifact(
            "AU-9",
            "The audit_events PostgreSQL table has REVOKE UPDATE, DELETE on the application \
             role. The AuditWriter trait has no update or delete methods. Only the archive \
             process (separate DB role) can move records.",
            "Review writer.rs trait definition. Check DB migration for REVOKE statement. \
             Run nist_au9_* tests.",
            ArtifactType::Configuration,
        )
        .add_artifact(
            "AU-12",
            "Every PrintForge crate emits structured audit events via the Auditable trait \
             or direct collector call. The collector validates, persists, and exports each \
             event.",
            "Review collector.rs. Run nist_au12_* tests.",
            ArtifactType::TestResult,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emass_builder_generates_sorted_artifacts() {
        let artifacts = EmassArtifactBuilder::new("PrintForge")
            .add_artifact(
                "SC-28",
                "Encryption at rest",
                "Check config",
                ArtifactType::Configuration,
            )
            .add_artifact(
                "AU-2",
                "Event logging",
                "Check catalog",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "AC-3",
                "Access enforcement",
                "Check RBAC",
                ArtifactType::TestResult,
            )
            .build();

        assert_eq!(artifacts.len(), 3);
        assert_eq!(artifacts[0].control_family, "AC");
        assert_eq!(artifacts[1].control_family, "AU");
        assert_eq!(artifacts[2].control_family, "SC");
    }

    #[test]
    fn emass_au_family_generates_five_controls() {
        let artifacts = EmassArtifactBuilder::new("PrintForge")
            .with_au_family()
            .build();

        assert_eq!(artifacts.len(), 5);
        let control_ids: Vec<&str> = artifacts.iter().map(|a| a.control_id.as_str()).collect();
        assert!(control_ids.contains(&"AU-2"));
        assert!(control_ids.contains(&"AU-3"));
        assert!(control_ids.contains(&"AU-6"));
        assert!(control_ids.contains(&"AU-9"));
        assert!(control_ids.contains(&"AU-12"));
    }

    #[test]
    fn emass_artifact_round_trips_json() {
        let artifacts = EmassArtifactBuilder::new("PrintForge")
            .add_artifact("AU-2", "impl", "assess", ArtifactType::TestResult)
            .build();

        let json = serde_json::to_string(&artifacts).unwrap();
        let deserialized: Vec<EmassArtifact> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized[0].control_id, "AU-2");
    }
}
