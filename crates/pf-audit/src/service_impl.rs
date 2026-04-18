// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default implementation of [`AuditService`] backed by an [`AuditRepository`].
//!
//! **NIST 800-53 Rev 5:** AU-6 — Audit Record Review, Analysis, and Reporting

use chrono::{DateTime, Utc};
use pf_common::audit::{AuditEvent, Outcome};
use tracing::info;

use crate::emass::{ArtifactType, EmassArtifact, EmassArtifactBuilder};
use crate::error::AuditError;
use crate::query::AuditQuery;
use crate::repository::AuditRepository;
use crate::service::{AuditService, NistEvidenceReport};

/// Default [`AuditService`] implementation that delegates to an
/// [`AuditRepository`] for persistence and builds eMASS evidence artifacts.
///
/// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
pub struct AuditServiceImpl<R> {
    repo: R,
    system_name: String,
}

impl<R: AuditRepository> AuditServiceImpl<R> {
    /// Create a new service backed by the given repository.
    #[must_use]
    pub fn new(repo: R, system_name: &str) -> Self {
        Self {
            repo,
            system_name: system_name.to_string(),
        }
    }
}

impl<R: AuditRepository + 'static> AuditService for AuditServiceImpl<R> {
    /// Query audit events with validation, delegation to the repository, and
    /// structured logging.
    ///
    /// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
    fn query_events(
        &self,
        query: AuditQuery,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(Vec<AuditEvent>, u64), AuditError>> + Send + '_>> {
        Box::pin(async move {
            query.validate()?;

            let result = self.repo.query(&query).await?;

            info!(
                total = result.total_count,
                returned = result.events.len(),
                offset = result.offset,
                limit = result.limit,
                "AU-6: audit query executed"
            );

            Ok((result.events, result.total_count))
        })
    }

    /// Generate a NIST evidence report for a control family over a time
    /// window.
    ///
    /// Steps:
    /// 1. Validate inputs.
    /// 2. Query events filtered by `nist_control` prefix matching the family.
    /// 3. Compute success/failure statistics.
    /// 4. Generate eMASS artifacts for the family.
    ///
    /// **NIST 800-53 Rev 5:** AU-6 — Audit Record Review
    fn export_nist_evidence(
        &self,
        control_family: String,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<NistEvidenceReport, AuditError>> + Send + '_>> {
        Box::pin(async move {
            // --- Validate inputs ---
            if control_family.trim().is_empty() {
                return Err(AuditError::InvalidQuery {
                    message: "control_family must not be empty".to_string(),
                });
            }

            if from >= to {
                return Err(AuditError::InvalidQuery {
                    message: "'from' must be before 'to'".to_string(),
                });
            }

            // --- Query events matching the control family ---
            let query = AuditQuery {
                nist_control: Some(control_family.clone()),
                from: Some(from),
                to: Some(to),
                limit: Some(10_000),
                ..AuditQuery::default()
            };
            // Validation is guaranteed to pass because we built valid params above.
            let result = self.repo.query(&query).await?;

            // --- Aggregate statistics ---
            let success_count = result
                .events
                .iter()
                .filter(|e| e.outcome == Outcome::Success)
                .count() as u64;
            let failure_count = result
                .events
                .iter()
                .filter(|e| e.outcome == Outcome::Failure)
                .count() as u64;

            // --- Build eMASS artifacts for the control family ---
            let artifacts = build_emass_artifacts(&control_family, &self.system_name);

            info!(
                control_family = control_family.as_str(),
                total_events = result.total_count,
                success_count,
                failure_count,
                artifacts = artifacts.len(),
                "AU-6: NIST evidence report generated"
            );

            Ok(NistEvidenceReport {
                control_family,
                from,
                to,
                generated_at: Utc::now(),
                total_events: result.total_count,
                success_count,
                failure_count,
                events: result.events,
                artifacts,
            })
        })
    }
}

/// Build eMASS artifacts for the requested control family using the
/// [`EmassArtifactBuilder`].
///
/// Known families (AU, AC, IA, SC, SI, CM, CP) get rich, pre-authored
/// descriptions. Unknown families get a generic placeholder artifact.
#[allow(clippy::too_many_lines)]
fn build_emass_artifacts(control_family: &str, system_name: &str) -> Vec<EmassArtifact> {
    let builder = EmassArtifactBuilder::new(system_name);

    match control_family {
        "AU" => builder.with_au_family().build(),

        "AC" => builder
            .add_artifact(
                "AC-2",
                "PrintForge implements JIT user provisioning via SCIM 2.0 and \
                 attribute sync. User lifecycle events (create, update, suspend, \
                 reactivate, role change) are logged as immutable audit records.",
                "Review pf-user-provisioning crate. Run nist_ac2_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "AC-3",
                "RBAC role checks are enforced on every API call in the \
                 pf-api-gateway middleware. Policy decisions from pf-policy-engine \
                 are logged as PolicyAllow / PolicyDeny events.",
                "Review pf-api-gateway RBAC middleware. Run nist_ac3_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "AC-7",
                "CAC PIN failure lockout and OIDC failure tracking are \
                 implemented in pf-auth. PinLockout events are emitted after \
                 the configured threshold is reached.",
                "Review pf-auth lockout logic. Run nist_ac7_* tests.",
                ArtifactType::TestResult,
            )
            .build(),

        "IA" => builder
            .add_artifact(
                "IA-2",
                "PrintForge authenticates users via CAC/PIV X.509 certificates, \
                 OIDC, and SAML. mTLS is enforced for service-to-service \
                 communication.",
                "Review pf-auth authentication flows. Run nist_ia2_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "IA-5",
                "Certificate chain validation against DoD PKI trust anchors. \
                 OCSP and CRL checks are performed for revocation status.",
                "Review pf-auth chain validation. Run nist_ia5_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "IA-5(2)",
                "Full chain validation from leaf certificate to DoD Root CA. \
                 Self-signed and expired intermediates are rejected.",
                "Review pf-auth PKI validation. Run nist_ia5_2_* tests.",
                ArtifactType::TestResult,
            )
            .build(),

        "SC" => builder
            .add_artifact(
                "SC-8",
                "TLS 1.2+ is enforced on all external and internal \
                 communications. IPPS endpoints require TLS. The service mesh \
                 uses mTLS.",
                "Review pf-api-gateway TLS config. Run nist_sc8_* tests.",
                ArtifactType::Configuration,
            )
            .add_artifact(
                "SC-12",
                "DEK/KEK key hierarchy with configurable rotation intervals. \
                 Key material is managed through pf-spool with FIPS 140-3 \
                 validated crypto.",
                "Review pf-spool key management. Run nist_sc12_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "SC-28",
                "AES-256-GCM encryption for all spool data at rest. Per-job \
                 DEK rotation on re-encryption.",
                "Review pf-spool encryption. Run nist_sc28_* tests.",
                ArtifactType::TestResult,
            )
            .build(),

        "SI" => builder
            .add_artifact(
                "SI-2",
                "cargo-audit and cargo-deny run in CI on every build to check \
                 for known vulnerabilities in dependencies.",
                "Review CI pipeline. Check cargo-audit output.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "SI-7",
                "Firmware images are cryptographically validated before \
                 deployment. Hash verification and signature checks are \
                 performed by pf-firmware-mgr.",
                "Review pf-firmware-mgr validation. Run nist_si7_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "SI-10",
                "All API inputs are validated using the newtype pattern. IPP \
                 attributes are sanitized before processing. Fuzz and property \
                 tests cover input validation.",
                "Review pf-api-gateway input validation. Run nist_si10_* tests.",
                ArtifactType::TestResult,
            )
            .build(),

        "CM" => builder
            .add_artifact(
                "CM-3",
                "Configuration changes (firmware deployments, printer additions \
                 and removals) are tracked as auditable events with full actor \
                 attribution.",
                "Review pf-fleet-mgr and pf-firmware-mgr change tracking. \
                 Run nist_cm3_* tests.",
                ArtifactType::TestResult,
            )
            .add_artifact(
                "CM-8",
                "SNMPv3 polling discovers and inventories all printers. Fleet \
                 status changes are logged as audit events.",
                "Review pf-fleet-mgr discovery. Run nist_cm8_* tests.",
                ArtifactType::TestResult,
            )
            .build(),

        "CP" => builder
            .add_artifact(
                "CP-7",
                "Edge cache nodes provide alternate processing capability \
                 during DDIL conditions. NATS leaf connections sync state \
                 when connectivity is restored.",
                "Review pf-cache-node DDIL mode. Run nist_cp7_* tests.",
                ArtifactType::TestResult,
            )
            .build(),

        // Unknown family — produce a generic placeholder
        _ => builder
            .add_artifact(
                control_family,
                &format!(
                    "Evidence for control family {control_family} collected from \
                     PrintForge audit log over the requested time window."
                ),
                "Review matching audit events in the report payload.",
                ArtifactType::SystemLog,
            )
            .build(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use chrono::{Duration, Utc};
    use pf_common::audit::{AuditEvent, EventKind, Outcome};
    use pf_common::identity::Edipi;
    use uuid::Uuid;

    use super::*;
    use crate::query::AuditQueryResult;

    // -----------------------------------------------------------------------
    // In-memory mock repository
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct MockRepo {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl MockRepo {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn add(&self, event: AuditEvent) {
            self.events.lock().expect("lock poisoned").push(event);
        }
    }

    impl AuditRepository for MockRepo {
        async fn insert(&self, event: &AuditEvent) -> Result<(), AuditError> {
            self.events
                .lock()
                .expect("lock poisoned")
                .push(event.clone());
            Ok(())
        }

        async fn query(&self, query: &AuditQuery) -> Result<AuditQueryResult, AuditError> {
            query.validate()?;

            let store = self.events.lock().expect("lock poisoned");
            let filtered = query.filter(&store);
            // Compute total count without pagination
            let total = store.iter().filter(|e| unpaginated_matches(query, e)).count() as u64;
            let limit = query.limit.unwrap_or(1000);
            let offset = query.offset.unwrap_or(0);

            Ok(AuditQueryResult {
                events: filtered,
                total_count: total,
                offset,
                limit,
            })
        }

        async fn count_online(&self) -> Result<u64, AuditError> {
            Ok(self.events.lock().expect("lock poisoned").len() as u64)
        }
    }

    /// Check if an event matches the query filters (ignoring pagination).
    fn unpaginated_matches(query: &AuditQuery, event: &AuditEvent) -> bool {
        let paginated = AuditQuery {
            limit: None,
            offset: None,
            ..query.clone()
        };
        paginated.filter(std::slice::from_ref(event)).len() == 1
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_event(
        action: EventKind,
        outcome: Outcome,
        nist_control: &str,
    ) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: Edipi::new("1234567890").unwrap(),
            action,
            target: "test-target".to_string(),
            outcome,
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            nist_control: Some(nist_control.to_string()),
        }
    }

    fn make_service() -> (MockRepo, AuditServiceImpl<MockRepo>) {
        let repo = MockRepo::new();
        let svc = AuditServiceImpl::new(repo.clone(), "PrintForge-Test");
        (repo, svc)
    }

    // -----------------------------------------------------------------------
    // query_events tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn nist_au6_query_events_returns_matching_events() {
        // NIST 800-53 Rev 5: AU-6 — Audit Record Review
        // Evidence: The service correctly delegates to the repository and
        // returns filtered events with a total count.
        let (repo, svc) = make_service();
        repo.add(make_event(EventKind::AuthSuccess, Outcome::Success, "IA-2"));
        repo.add(make_event(EventKind::AuthFailure, Outcome::Failure, "IA-2"));
        repo.add(make_event(EventKind::JobSubmitted, Outcome::Success, "AU-12"));

        let query = AuditQuery {
            actions: Some(vec![EventKind::AuthSuccess]),
            ..AuditQuery::default()
        };

        let (events, total) = svc.query_events(query).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(total, 1);
        assert_eq!(events[0].action, EventKind::AuthSuccess);
    }

    #[tokio::test]
    async fn query_events_rejects_invalid_query() {
        let (_repo, svc) = make_service();

        let query = AuditQuery {
            limit: Some(99_999),
            ..AuditQuery::default()
        };

        let result = svc.query_events(query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn query_events_returns_empty_for_no_matches() {
        let (_repo, svc) = make_service();

        let query = AuditQuery {
            actions: Some(vec![EventKind::FirmwareRollback]),
            ..AuditQuery::default()
        };

        let (events, total) = svc.query_events(query).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn nist_au6_query_events_pagination() {
        // NIST 800-53 Rev 5: AU-6 — Audit Record Review
        // Evidence: Pagination parameters are forwarded correctly.
        let (repo, svc) = make_service();
        for _ in 0..5 {
            repo.add(make_event(EventKind::AuthSuccess, Outcome::Success, "IA-2"));
        }

        let query = AuditQuery {
            limit: Some(2),
            offset: Some(0),
            ..AuditQuery::default()
        };

        let (events, total) = svc.query_events(query).await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(total, 5);
    }

    // -----------------------------------------------------------------------
    // export_nist_evidence tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn nist_au6_export_evidence_aggregates_statistics() {
        // NIST 800-53 Rev 5: AU-6 — Audit Record Review
        // Evidence: The evidence report correctly aggregates success and
        // failure counts for the requested control family.
        let (repo, svc) = make_service();
        repo.add(make_event(EventKind::AuthSuccess, Outcome::Success, "IA"));
        repo.add(make_event(EventKind::AuthFailure, Outcome::Failure, "IA"));
        repo.add(make_event(EventKind::AuthFailure, Outcome::Failure, "IA"));
        // Different family — should not appear
        repo.add(make_event(EventKind::JobSubmitted, Outcome::Success, "AU"));

        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);

        let report = svc.export_nist_evidence("IA".to_string(), from, to).await.unwrap();

        assert_eq!(report.control_family, "IA");
        assert_eq!(report.total_events, 3);
        assert_eq!(report.success_count, 1);
        assert_eq!(report.failure_count, 2);
        assert_eq!(report.events.len(), 3);
        assert!(!report.artifacts.is_empty());
    }

    #[tokio::test]
    async fn export_evidence_rejects_empty_family() {
        let (_repo, svc) = make_service();
        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);

        let result = svc.export_nist_evidence(String::new(), from, to).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn export_evidence_rejects_from_after_to() {
        let (_repo, svc) = make_service();
        let now = Utc::now();

        let result = svc
            .export_nist_evidence("AU".to_string(), now, now - Duration::hours(1))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn export_evidence_returns_emass_artifacts_for_au_family() {
        let (_repo, svc) = make_service();
        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);

        let report = svc.export_nist_evidence("AU".to_string(), from, to).await.unwrap();

        // AU family should produce 5 artifacts (AU-2, AU-3, AU-6, AU-9, AU-12)
        assert_eq!(report.artifacts.len(), 5);
        let ids: Vec<&str> = report
            .artifacts
            .iter()
            .map(|a| a.control_id.as_str())
            .collect();
        assert!(ids.contains(&"AU-2"));
        assert!(ids.contains(&"AU-3"));
        assert!(ids.contains(&"AU-6"));
        assert!(ids.contains(&"AU-9"));
        assert!(ids.contains(&"AU-12"));
    }

    #[tokio::test]
    async fn export_evidence_handles_unknown_family() {
        let (_repo, svc) = make_service();
        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);

        let report = svc.export_nist_evidence("ZZ".to_string(), from, to).await.unwrap();

        assert_eq!(report.control_family, "ZZ");
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.artifacts[0].control_id, "ZZ");
    }

    #[tokio::test]
    async fn export_evidence_report_serializes_to_json() {
        let (_repo, svc) = make_service();
        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);

        let report = svc.export_nist_evidence("AU".to_string(), from, to).await.unwrap();
        let json = serde_json::to_string(&report).unwrap();

        assert!(json.contains("\"control_family\":\"AU\""));
    }
}
