// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Default implementation of [`FleetService`] backed by a [`PrinterRepository`].
//!
//! Maps between persistence-layer `PrinterRecord` types and API-facing view types
//! (`PrinterSummary`, `PrinterDetail`, `PrinterStatusInfo`).
//!
//! **NIST 800-53 Rev 5:** CM-8 — System Component Inventory, SI-4 — System Monitoring

use pf_common::fleet::PrinterId;

use crate::error::FleetError;
use crate::health::{
    HealthInput, HealthWeights, compute_health_score,
};
use crate::inventory::{PrinterQuery, PrinterRecord};
use crate::repository::PrinterRepository;
use crate::service::{
    FleetService, PrinterDetail, PrinterStatusInfo, PrinterSummary,
};

/// Default [`FleetService`] implementation.
///
/// Delegates persistence to an injected [`PrinterRepository`] and applies
/// business logic such as health score computation and type mapping.
pub struct FleetServiceImpl<R> {
    repo: R,
    health_weights: HealthWeights,
}

impl<R> FleetServiceImpl<R> {
    /// Create a new `FleetServiceImpl` with the given repository and default health weights.
    #[must_use]
    pub fn new(repo: R) -> Self {
        Self {
            repo,
            health_weights: HealthWeights::default(),
        }
    }

    /// Create a new `FleetServiceImpl` with custom health weights.
    ///
    /// # Errors
    ///
    /// Returns an error string if the weights do not sum to 100.
    pub fn with_weights(repo: R, weights: HealthWeights) -> Result<Self, String> {
        weights.validate()?;
        Ok(Self {
            repo,
            health_weights: weights,
        })
    }
}

/// Convert a `PrinterRecord` into a `PrinterSummary` (list view).
fn to_summary(record: &PrinterRecord) -> PrinterSummary {
    PrinterSummary {
        id: record.id.clone(),
        model: record.model.clone(),
        status: record.status,
        location: record.location.clone(),
        supply_levels: record.supply_levels,
        health_score: record.health_score,
        updated_at: record.updated_at,
        last_polled_at: record.last_polled_at,
    }
}

/// Convert a `PrinterRecord` into a `PrinterDetail` (detail view).
fn to_detail(record: &PrinterRecord) -> PrinterDetail {
    PrinterDetail {
        id: record.id.clone(),
        model: record.model.clone(),
        serial_number: record.serial_number.clone(),
        firmware_version: record.firmware_version.clone(),
        ip_address: record.ip_address,
        hostname: record.hostname.clone(),
        location: record.location.clone(),
        status: record.status,
        supply_levels: record.supply_levels,
        health_score: record.health_score,
        total_page_count: record.total_page_count,
        registered_at: record.registered_at,
        updated_at: record.updated_at,
        last_polled_at: record.last_polled_at,
    }
}

/// Build a `PrinterStatusInfo` from a `PrinterRecord`, computing a fresh health score.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn to_status_info(
    record: &PrinterRecord,
    weights: &HealthWeights,
) -> Result<PrinterStatusInfo, FleetError> {
    let health_input = HealthInput {
        status: record.status,
        is_reachable: record.status != pf_common::fleet::PrinterStatus::Offline,
        consecutive_failures: record.consecutive_poll_failures,
        supply_levels: record.supply_levels,
        queue_depth: 0, // Queue depth is not stored on the record; default to 0.
        queue_capacity: 50,
        firmware_current: true, // Firmware currency requires cross-crate check; default to true.
        active_error_count: u32::from(record.status == pf_common::fleet::PrinterStatus::Error),
    };

    let health_score = compute_health_score(&health_input, weights)
        .map_err(FleetError::HealthScore)?;

    Ok(PrinterStatusInfo {
        id: record.id.clone(),
        status: record.status,
        supply_levels: record.supply_levels,
        health_score: Some(health_score),
        last_polled_at: record.last_polled_at,
        consecutive_poll_failures: record.consecutive_poll_failures,
    })
}

impl<R: PrinterRepository + 'static> FleetService for FleetServiceImpl<R> {
    fn list_printers(
        &self,
        filter: PrinterQuery,
        limit: u32,
        offset: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(Vec<PrinterSummary>, u64), FleetError>> + Send + '_>> {
        Box::pin(async move {
            // Build a paginated query from the caller's filter.
            let paginated = PrinterQuery {
                limit: Some(limit),
                offset: Some(offset),
                ..filter.clone()
            };

            let records = self.repo.query(&paginated).await?;
            let summaries: Vec<PrinterSummary> = records.iter().map(to_summary).collect();

            // Get total count from the fleet summary for the total matching records.
            // In a production system we would add a `count` method to the repository;
            // for now we use the summary total as a reasonable approximation when no
            // filters are applied, or the length of an unfiltered query otherwise.
            let total = if filter_is_empty(&filter) {
                let summary = self.repo.summary().await?;
                summary.total_printers
            } else {
                // Run an unbounded query to get total count for filtered results.
                let count_query = PrinterQuery {
                    limit: None,
                    offset: None,
                    ..filter.clone()
                };
                let all = self.repo.query(&count_query).await?;
                all.len() as u64
            };

            Ok((summaries, total))
        })
    }

    fn get_printer(
        &self,
        id: PrinterId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PrinterDetail, FleetError>> + Send + '_>> {
        Box::pin(async move {
            let record = self.repo.get_by_id(&id).await?;
            Ok(to_detail(&record))
        })
    }

    fn get_printer_status(
        &self,
        id: PrinterId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PrinterStatusInfo, FleetError>> + Send + '_>> {
        Box::pin(async move {
            let record = self.repo.get_by_id(&id).await?;
            to_status_info(&record, &self.health_weights)
        })
    }
}

/// Returns `true` if no filter criteria are set on the query.
fn filter_is_empty(q: &PrinterQuery) -> bool {
    q.installation.is_none()
        && q.installations.is_empty()
        && q.building.is_none()
        && q.status.is_none()
        && q.vendor.is_none()
        && q.model.is_none()
        && q.health_below.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use pf_common::fleet::{PrinterModel, PrinterStatus, SupplyLevel};
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::discovery::{DiscoveryMethod, PrinterLocation};
    use crate::inventory::{FleetSummary, PrinterUpdate};

    /// In-memory mock implementation of [`PrinterRepository`] for testing.
    struct MockRepository {
        printers: Mutex<HashMap<String, PrinterRecord>>,
    }

    impl MockRepository {
        fn new() -> Self {
            Self {
                printers: Mutex::new(HashMap::new()),
            }
        }

        fn with_records(records: Vec<PrinterRecord>) -> Self {
            let mut map = HashMap::new();
            for r in records {
                map.insert(r.id.as_str().to_string(), r);
            }
            Self {
                printers: Mutex::new(map),
            }
        }
    }

    impl PrinterRepository for MockRepository {
        async fn insert(&self, record: &PrinterRecord) -> Result<(), FleetError> {
            let mut map = self.printers.lock().unwrap();
            let key = record.id.as_str().to_string();
            if map.contains_key(&key) {
                return Err(FleetError::Validation(
                    pf_common::error::ValidationError::InvalidPrinterId(key),
                ));
            }
            map.insert(key, record.clone());
            Ok(())
        }

        async fn get_by_id(&self, id: &PrinterId) -> Result<PrinterRecord, FleetError> {
            let map = self.printers.lock().unwrap();
            map.get(id.as_str())
                .cloned()
                .ok_or(FleetError::PrinterNotFound)
        }

        async fn update(
            &self,
            id: &PrinterId,
            update: &PrinterUpdate,
        ) -> Result<(), FleetError> {
            let mut map = self.printers.lock().unwrap();
            let record = map
                .get_mut(id.as_str())
                .ok_or(FleetError::PrinterNotFound)?;
            if let Some(ip) = update.ip_address {
                record.ip_address = ip;
            }
            if let Some(ref fw) = update.firmware_version {
                record.firmware_version = fw.clone();
            }
            Ok(())
        }

        async fn delete(&self, id: &PrinterId) -> Result<(), FleetError> {
            let mut map = self.printers.lock().unwrap();
            if map.remove(id.as_str()).is_none() {
                return Err(FleetError::PrinterNotFound);
            }
            Ok(())
        }

        async fn query(&self, query: &PrinterQuery) -> Result<Vec<PrinterRecord>, FleetError> {
            let map = self.printers.lock().unwrap();
            let mut results: Vec<PrinterRecord> = map
                .values()
                .filter(|r| {
                    if let Some(ref inst) = query.installation {
                        if r.location.installation != *inst {
                            return false;
                        }
                    }
                    if !query.installations.is_empty()
                        && !query.installations.contains(&r.location.installation)
                    {
                        return false;
                    }
                    if let Some(ref building) = query.building {
                        if r.location.building != *building {
                            return false;
                        }
                    }
                    if let Some(status) = query.status {
                        if r.status != status {
                            return false;
                        }
                    }
                    if let Some(ref vendor) = query.vendor {
                        if r.model.vendor != *vendor {
                            return false;
                        }
                    }
                    if let Some(ref model) = query.model {
                        if !r.model.model.contains(model.as_str()) {
                            return false;
                        }
                    }
                    if let Some(threshold) = query.health_below {
                        if let Some(score) = r.health_score {
                            if score >= threshold {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();

            // Sort by ID for deterministic results.
            results.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

            // Apply pagination.
            let offset = query.offset.unwrap_or(0) as usize;
            let limit = query.limit.unwrap_or(u32::MAX) as usize;
            let paginated = results.into_iter().skip(offset).take(limit).collect();
            Ok(paginated)
        }

        async fn summary(&self) -> Result<FleetSummary, FleetError> {
            let map = self.printers.lock().unwrap();
            let total = map.len() as u64;
            let online = map.values().filter(|r| r.status == PrinterStatus::Online).count() as u64;
            let offline = map.values().filter(|r| r.status == PrinterStatus::Offline).count() as u64;
            let error = map.values().filter(|r| r.status == PrinterStatus::Error).count() as u64;
            let maintenance = map
                .values()
                .filter(|r| r.status == PrinterStatus::Maintenance)
                .count() as u64;
            let scores: Vec<f64> = map
                .values()
                .filter_map(|r| r.health_score.map(f64::from))
                .collect();
            let avg = if scores.is_empty() {
                0.0
            } else {
                #[allow(clippy::cast_precision_loss)] // printer count fits in f64
                { scores.iter().sum::<f64>() / scores.len() as f64 }
            };
            Ok(FleetSummary {
                total_printers: total,
                online_count: online,
                offline_count: offline,
                error_count: error,
                maintenance_count: maintenance,
                average_health_score: avg,
                critical_supply_count: 0,
            })
        }

        async fn list_ids(&self) -> Result<Vec<PrinterId>, FleetError> {
            let map = self.printers.lock().unwrap();
            Ok(map.values().map(|r| r.id.clone()).collect())
        }
    }

    fn make_test_record(id: &str, status: PrinterStatus) -> PrinterRecord {
        PrinterRecord {
            id: PrinterId::new(id).unwrap(),
            model: PrinterModel {
                vendor: "TestVendor".to_string(),
                model: "TestModel 9000".to_string(),
            },
            serial_number: format!("SN-{id}"),
            firmware_version: "1.0.0".to_string(),
            ip_address: "10.0.1.100".parse().unwrap(),
            hostname: Some(format!("{id}.test.mil")),
            location: PrinterLocation {
                installation: "Test Base AFB".to_string(),
                building: "100".to_string(),
                floor: "1".to_string(),
                room: "101".to_string(),
            },
            discovery_method: DiscoveryMethod::Manual,
            status,
            supply_levels: Some(SupplyLevel {
                toner_k: 80,
                toner_c: 75,
                toner_m: 90,
                toner_y: 85,
                paper: 70,
            }),
            health_score: Some(90),
            total_page_count: Some(1000),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            last_polled_at: Some(Utc::now()),
            consecutive_poll_failures: 0,
        }
    }

    #[tokio::test]
    async fn nist_cm8_list_printers_returns_inventory() {
        // NIST CM-8: System Component Inventory
        // Verifies that the fleet service can list all printers in inventory.
        let repo = MockRepository::with_records(vec![
            make_test_record("PRN-0001", PrinterStatus::Online),
            make_test_record("PRN-0002", PrinterStatus::Offline),
            make_test_record("PRN-0003", PrinterStatus::Online),
        ]);
        let svc = FleetServiceImpl::new(repo);

        let (printers, total) = svc
            .list_printers(PrinterQuery::default(), 10, 0)
            .await
            .unwrap();

        assert_eq!(printers.len(), 3);
        assert_eq!(total, 3);
    }

    #[tokio::test]
    async fn list_printers_respects_pagination() {
        let repo = MockRepository::with_records(vec![
            make_test_record("PRN-0001", PrinterStatus::Online),
            make_test_record("PRN-0002", PrinterStatus::Online),
            make_test_record("PRN-0003", PrinterStatus::Online),
        ]);
        let svc = FleetServiceImpl::new(repo);

        // Page 1: limit 2, offset 0
        let (page1, total) = svc
            .list_printers(PrinterQuery::default(), 2, 0)
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(total, 3);

        // Page 2: limit 2, offset 2
        let (page2, _) = svc
            .list_printers(PrinterQuery::default(), 2, 2)
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
    }

    #[tokio::test]
    async fn list_printers_applies_status_filter() {
        let repo = MockRepository::with_records(vec![
            make_test_record("PRN-0001", PrinterStatus::Online),
            make_test_record("PRN-0002", PrinterStatus::Offline),
            make_test_record("PRN-0003", PrinterStatus::Online),
        ]);
        let svc = FleetServiceImpl::new(repo);

        let filter = PrinterQuery {
            status: Some(PrinterStatus::Online),
            ..Default::default()
        };
        let (printers, total) = svc.list_printers(filter, 10, 0).await.unwrap();

        assert_eq!(printers.len(), 2);
        assert_eq!(total, 2);
        for p in &printers {
            assert_eq!(p.status, PrinterStatus::Online);
        }
    }

    #[tokio::test]
    async fn nist_cm8_get_printer_returns_full_detail() {
        // NIST CM-8: System Component Inventory
        // Verifies that full hardware, firmware, network, and location detail is returned.
        let repo = MockRepository::with_records(vec![
            make_test_record("PRN-0001", PrinterStatus::Online),
        ]);
        let svc = FleetServiceImpl::new(repo);

        let detail = svc
            .get_printer(PrinterId::new("PRN-0001").unwrap())
            .await
            .unwrap();

        assert_eq!(detail.id.as_str(), "PRN-0001");
        assert_eq!(detail.model.vendor, "TestVendor");
        assert!(!detail.serial_number.is_empty());
        assert!(!detail.firmware_version.is_empty());
        assert!(!detail.location.installation.is_empty());
    }

    #[tokio::test]
    async fn get_printer_not_found_returns_error() {
        let repo = MockRepository::new();
        let svc = FleetServiceImpl::new(repo);

        let result = svc
            .get_printer(PrinterId::new("PRN-9999").unwrap())
            .await;

        assert!(matches!(result, Err(FleetError::PrinterNotFound)));
    }

    #[tokio::test]
    async fn nist_si4_get_printer_status_returns_monitoring_data() {
        // NIST SI-4: System Monitoring
        // Verifies that status, supply levels, and health score are returned.
        let repo = MockRepository::with_records(vec![
            make_test_record("PRN-0001", PrinterStatus::Online),
        ]);
        let svc = FleetServiceImpl::new(repo);

        let status = svc
            .get_printer_status(PrinterId::new("PRN-0001").unwrap())
            .await
            .unwrap();

        assert_eq!(status.id.as_str(), "PRN-0001");
        assert_eq!(status.status, PrinterStatus::Online);
        assert!(status.supply_levels.is_some());
        assert!(status.health_score.is_some());
        assert_eq!(status.consecutive_poll_failures, 0);
    }

    #[tokio::test]
    async fn get_printer_status_not_found_returns_error() {
        let repo = MockRepository::new();
        let svc = FleetServiceImpl::new(repo);

        let result = svc
            .get_printer_status(PrinterId::new("PRN-9999").unwrap())
            .await;

        assert!(matches!(result, Err(FleetError::PrinterNotFound)));
    }

    #[tokio::test]
    async fn nist_si4_status_computes_health_score() {
        // NIST SI-4: System Monitoring
        // Verifies that the health score is freshly computed from printer state.
        let mut record = make_test_record("PRN-0001", PrinterStatus::Error);
        record.consecutive_poll_failures = 3;
        record.supply_levels = Some(SupplyLevel {
            toner_k: 5,
            toner_c: 5,
            toner_m: 5,
            toner_y: 5,
            paper: 5,
        });

        let repo = MockRepository::with_records(vec![record]);
        let svc = FleetServiceImpl::new(repo);

        let status = svc
            .get_printer_status(PrinterId::new("PRN-0001").unwrap())
            .await
            .unwrap();

        let score = status.health_score.expect("health score should be computed");
        // An error-state printer with low supplies should score poorly.
        assert!(
            score.overall < 50,
            "error printer with low supplies scored {} (expected < 50)",
            score.overall
        );
    }

    #[tokio::test]
    async fn custom_health_weights_are_applied() {
        let repo = MockRepository::with_records(vec![
            make_test_record("PRN-0001", PrinterStatus::Online),
        ]);

        let weights = HealthWeights {
            connectivity: 50,
            error_state: 10,
            supply_levels: 10,
            queue_depth: 10,
            firmware_currency: 20,
        };
        let svc = FleetServiceImpl::with_weights(repo, weights).unwrap();

        let status = svc
            .get_printer_status(PrinterId::new("PRN-0001").unwrap())
            .await
            .unwrap();

        assert!(status.health_score.is_some());
    }

    #[test]
    fn invalid_weights_rejected_at_construction() {
        let weights = HealthWeights {
            connectivity: 50,
            error_state: 50,
            supply_levels: 50,
            queue_depth: 50,
            firmware_currency: 50,
        };
        let repo = MockRepository::new();
        let result = FleetServiceImpl::with_weights(repo, weights);
        assert!(result.is_err());
    }
}
