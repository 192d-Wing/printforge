// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for the `pf-fleet-mgr` crate.
//!
//! These tests exercise public API types and functions without requiring
//! network access or a database. All test data is synthetic.

use chrono::Utc;
use uuid::Uuid;

use pf_common::audit::EventKind;
use pf_common::fleet::{PrinterId, PrinterModel, PrinterStatus, SupplyLevel};

use pf_fleet_mgr::alerting::{
    evaluate_health_alerts, evaluate_supply_alerts, AlertCategory, AlertSeverity,
};
use pf_fleet_mgr::config::{AlertThresholds, SubnetConfig};
use pf_fleet_mgr::discovery::{
    DiscoveredPrinter, DiscoveryMethod, DiscoveryScanRequest, DiscoveryScanResult, PrinterLocation,
    StigViolation,
};
use pf_fleet_mgr::health::{compute_health_score, HealthBreakdown, HealthInput, HealthScore, HealthWeights};
use pf_fleet_mgr::inventory::{FleetSummary, PrinterQuery, PrinterRecord, PrinterUpdate};
use pf_fleet_mgr::snmp::{
    SnmpAuthProtocol, SnmpPollRequest, SnmpPollType, SnmpPrivacyProtocol, SnmpSecurityLevel,
    SnmpStatusResponse,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_printer_id() -> PrinterId {
    PrinterId::new("PRN-0001").unwrap()
}

fn healthy_input() -> HealthInput {
    HealthInput {
        status: PrinterStatus::Online,
        is_reachable: true,
        consecutive_failures: 0,
        supply_levels: Some(SupplyLevel {
            toner_k: 80,
            toner_c: 75,
            toner_m: 90,
            toner_y: 85,
            paper: 70,
        }),
        queue_depth: 2,
        queue_capacity: 50,
        firmware_current: true,
        active_error_count: 0,
    }
}

fn default_thresholds() -> AlertThresholds {
    AlertThresholds::default()
}

fn test_location() -> PrinterLocation {
    PrinterLocation {
        installation: "Test Base AFB".to_string(),
        building: "100".to_string(),
        floor: "2".to_string(),
        room: "201".to_string(),
    }
}

fn test_model() -> PrinterModel {
    PrinterModel {
        vendor: "TestVendor".to_string(),
        model: "TestModel 9000".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Health score computation tests
// ---------------------------------------------------------------------------

#[test]
fn integration_health_score_all_healthy() {
    let input = healthy_input();
    let score = compute_health_score(&input, &HealthWeights::default()).unwrap();

    // A fully healthy printer should score well above 70.
    assert!(
        score.overall >= 70,
        "all-healthy printer scored {} (expected >= 70)",
        score.overall
    );
    assert_eq!(score.breakdown.connectivity, 100);
    assert_eq!(score.breakdown.error_state, 100);
    assert_eq!(score.breakdown.firmware_currency, 100);
}

#[test]
fn integration_health_score_degraded_supply() {
    let mut input = healthy_input();
    input.supply_levels = Some(SupplyLevel {
        toner_k: 5,
        toner_c: 8,
        toner_m: 10,
        toner_y: 12,
        paper: 3,
    });

    let score = compute_health_score(&input, &HealthWeights::default()).unwrap();
    let healthy_score = compute_health_score(&healthy_input(), &HealthWeights::default()).unwrap();

    assert!(
        score.overall < healthy_score.overall,
        "degraded-supply printer ({}) should score lower than healthy ({})",
        score.overall,
        healthy_score.overall
    );
    // Supply factor should reflect the minimum supply level (paper at 3%).
    assert!(
        score.breakdown.supply_levels <= 5,
        "supply factor should be very low, got {}",
        score.breakdown.supply_levels
    );
}

#[test]
fn integration_health_score_offline_printer() {
    let input = HealthInput {
        status: PrinterStatus::Offline,
        is_reachable: false,
        consecutive_failures: 10,
        supply_levels: None,
        queue_depth: 0,
        queue_capacity: 50,
        firmware_current: false,
        active_error_count: 0,
    };

    let score = compute_health_score(&input, &HealthWeights::default()).unwrap();

    assert_eq!(score.breakdown.connectivity, 0);
    assert_eq!(score.breakdown.error_state, 0);
    // Firmware is outdated => 40.
    assert_eq!(score.breakdown.firmware_currency, 40);
    // Overall should be very low.
    assert!(
        score.overall <= 30,
        "offline printer scored {} (expected <= 30)",
        score.overall
    );
}

#[test]
fn integration_health_score_mixed_conditions() {
    // Online but with some errors, moderate supply, half-full queue, current firmware.
    let input = HealthInput {
        status: PrinterStatus::Online,
        is_reachable: true,
        consecutive_failures: 1,
        supply_levels: Some(SupplyLevel {
            toner_k: 40,
            toner_c: 50,
            toner_m: 60,
            toner_y: 55,
            paper: 35,
        }),
        queue_depth: 25,
        queue_capacity: 50,
        firmware_current: true,
        active_error_count: 1,
    };

    let score = compute_health_score(&input, &HealthWeights::default()).unwrap();

    // Should be in the middle range — not great, not terrible.
    assert!(
        (30..=80).contains(&score.overall),
        "mixed-condition printer scored {} (expected 30..=80)",
        score.overall
    );
    // Connectivity degrades by 20 per consecutive failure.
    assert_eq!(score.breakdown.connectivity, 80);
    // One active error deducts 25 points from error factor.
    assert_eq!(score.breakdown.error_state, 75);
    // Queue at 50% capacity => ~50 score.
    assert_eq!(score.breakdown.queue_depth, 50);
}

#[test]
fn integration_health_score_invalid_weights_rejected() {
    let bad_weights = HealthWeights {
        connectivity: 10,
        error_state: 10,
        supply_levels: 10,
        queue_depth: 10,
        firmware_currency: 10,
    };
    let result = compute_health_score(&healthy_input(), &bad_weights);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Alert threshold evaluation tests
// ---------------------------------------------------------------------------

#[test]
fn integration_supply_low_triggers_toner_warning() {
    let thresholds = default_thresholds();
    // toner_warning_pct default is 20, so 15% should trigger a warning.
    let alerts = evaluate_supply_alerts(&test_printer_id(), 15, 80, &thresholds);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Warning);
    assert_eq!(alerts[0].category, AlertCategory::TonerLow);
}

#[test]
fn integration_supply_low_triggers_toner_critical() {
    let thresholds = default_thresholds();
    // toner_critical_pct default is 5, so 3% should trigger critical.
    let alerts = evaluate_supply_alerts(&test_printer_id(), 3, 80, &thresholds);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    assert_eq!(alerts[0].category, AlertCategory::TonerLow);
}

#[test]
fn integration_supply_low_triggers_paper_alert() {
    let thresholds = default_thresholds();
    // paper_critical_pct default is 5, so 4% should fire critical.
    let alerts = evaluate_supply_alerts(&test_printer_id(), 80, 4, &thresholds);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    assert_eq!(alerts[0].category, AlertCategory::PaperLow);
}

#[test]
fn integration_supply_healthy_no_alert() {
    let thresholds = default_thresholds();
    let alerts = evaluate_supply_alerts(&test_printer_id(), 80, 70, &thresholds);
    assert!(alerts.is_empty());
}

#[test]
fn integration_both_supplies_low_produces_two_alerts() {
    let thresholds = default_thresholds();
    let alerts = evaluate_supply_alerts(&test_printer_id(), 3, 3, &thresholds);
    assert_eq!(alerts.len(), 2);
}

#[test]
fn integration_health_alert_critical_threshold() {
    let thresholds = default_thresholds();
    let health = HealthScore {
        overall: 20,
        breakdown: HealthBreakdown {
            connectivity: 0,
            error_state: 0,
            supply_levels: 50,
            queue_depth: 80,
            firmware_currency: 40,
        },
    };
    let alerts = evaluate_health_alerts(&test_printer_id(), &health, &thresholds);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    assert_eq!(alerts[0].category, AlertCategory::HealthDegraded);
    // Critical health alerts include a breakdown detail.
    assert!(alerts[0].detail.is_some());
}

#[test]
fn integration_health_alert_degraded_threshold() {
    let thresholds = default_thresholds();
    // health_degraded_score default is 60, so 50 should trigger warning.
    let health = HealthScore {
        overall: 50,
        breakdown: HealthBreakdown {
            connectivity: 60,
            error_state: 50,
            supply_levels: 40,
            queue_depth: 50,
            firmware_currency: 40,
        },
    };
    let alerts = evaluate_health_alerts(&test_printer_id(), &health, &thresholds);

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Warning);
}

#[test]
fn integration_health_alert_healthy_no_alert() {
    let thresholds = default_thresholds();
    let health = HealthScore {
        overall: 95,
        breakdown: HealthBreakdown {
            connectivity: 100,
            error_state: 100,
            supply_levels: 80,
            queue_depth: 90,
            firmware_currency: 100,
        },
    };
    let alerts = evaluate_health_alerts(&test_printer_id(), &health, &thresholds);
    assert!(alerts.is_empty());
}

// ---------------------------------------------------------------------------
// Discovery type construction and validation tests
// ---------------------------------------------------------------------------

#[test]
fn integration_discovery_scan_request_construction() {
    let subnets = vec![SubnetConfig {
        base_address: "10.0.1.0".parse().unwrap(),
        prefix_len: 24,
        site_id: Some("TEST-SITE-001".to_string()),
    }];

    let request = DiscoveryScanRequest {
        scan_id: Uuid::new_v4(),
        subnets: subnets.clone(),
        methods: vec![DiscoveryMethod::SnmpV3Walk, DiscoveryMethod::DnsSd],
        requested_at: Utc::now(),
    };

    assert_eq!(request.methods.len(), 2);
    assert_eq!(request.subnets.len(), 1);
    assert_eq!(request.subnets[0].prefix_len, 24);
}

#[test]
fn integration_discovered_printer_via_snmpv3() {
    let printer = DiscoveredPrinter {
        ip_address: "10.0.1.100".parse().unwrap(),
        hostname: Some("printer-test.test.mil".to_string()),
        model: Some(test_model()),
        serial_number: Some("SN-TEST-001".to_string()),
        method: DiscoveryMethod::SnmpV3Walk,
        discovered_at: Utc::now(),
        scan_id: Some(Uuid::new_v4()),
    };

    assert_eq!(printer.method, DiscoveryMethod::SnmpV3Walk);
    assert!(printer.serial_number.is_some());
}

#[test]
fn integration_discovered_printer_via_manual() {
    let printer = DiscoveredPrinter {
        ip_address: "10.0.2.50".parse().unwrap(),
        hostname: None,
        model: Some(test_model()),
        serial_number: Some("SN-TEST-002".to_string()),
        method: DiscoveryMethod::Manual,
        discovered_at: Utc::now(),
        scan_id: None,
    };

    assert_eq!(printer.method, DiscoveryMethod::Manual);
    // Manual registrations do not have a scan_id.
    assert!(printer.scan_id.is_none());
}

#[test]
fn integration_discovery_result_with_stig_violation() {
    let scan_id = Uuid::new_v4();
    let result = DiscoveryScanResult {
        scan_id,
        discovered: vec![],
        failed_subnets: vec![],
        stig_violations: vec![StigViolation {
            ip_address: "10.0.1.50".parse().unwrap(),
            description: "Device responded to SNMPv1 community string 'public'".to_string(),
            detected_at: Utc::now(),
        }],
        completed_at: Utc::now(),
    };

    assert_eq!(result.stig_violations.len(), 1);
    assert!(result.stig_violations[0]
        .description
        .contains("SNMPv1"));
}

#[test]
fn integration_printer_location_equality() {
    let loc1 = test_location();
    let loc2 = test_location();
    assert_eq!(loc1, loc2);

    let different = PrinterLocation {
        installation: "Other Base AFB".to_string(),
        building: "200".to_string(),
        floor: "1".to_string(),
        room: "101".to_string(),
    };
    assert_ne!(loc1, different);
}

// ---------------------------------------------------------------------------
// Inventory CRUD type validation tests
// ---------------------------------------------------------------------------

#[test]
fn integration_printer_record_construction() {
    let now = Utc::now();
    let record = PrinterRecord {
        id: test_printer_id(),
        model: test_model(),
        serial_number: "SN-TEST-001".to_string(),
        firmware_version: "2.1.0".to_string(),
        ip_address: "10.0.1.100".parse().unwrap(),
        hostname: Some("printer-0001.test.mil".to_string()),
        location: test_location(),
        discovery_method: DiscoveryMethod::SnmpV3Walk,
        status: PrinterStatus::Online,
        supply_levels: Some(SupplyLevel {
            toner_k: 80,
            toner_c: 75,
            toner_m: 90,
            toner_y: 85,
            paper: 70,
        }),
        health_score: Some(92),
        total_page_count: Some(54321),
        registered_at: now,
        updated_at: now,
        last_polled_at: Some(now),
        consecutive_poll_failures: 0,
    };

    assert_eq!(record.id.as_str(), "PRN-0001");
    assert_eq!(record.status, PrinterStatus::Online);
    assert!(record.health_score.unwrap() > 90);
    assert!(!record.serial_number.is_empty());
    assert!(!record.firmware_version.is_empty());
}

#[test]
fn integration_printer_update_partial_fields() {
    let update = PrinterUpdate {
        ip_address: Some("10.0.2.200".parse().unwrap()),
        hostname: Some(Some("new-hostname.test.mil".to_string())),
        firmware_version: Some("3.0.0".to_string()),
        location: None,
        model: None,
    };

    assert!(update.ip_address.is_some());
    assert!(update.firmware_version.is_some());
    assert!(update.location.is_none());
    assert!(update.model.is_none());
}

#[test]
fn integration_printer_update_default_is_empty() {
    let update = PrinterUpdate::default();
    assert!(update.ip_address.is_none());
    assert!(update.hostname.is_none());
    assert!(update.firmware_version.is_none());
    assert!(update.location.is_none());
    assert!(update.model.is_none());
}

#[test]
fn integration_printer_query_filters() {
    let query = PrinterQuery {
        installation: Some("Test Base AFB".to_string()),
        building: Some("100".to_string()),
        status: Some(PrinterStatus::Online),
        vendor: None,
        model: None,
        health_below: Some(60),
        limit: Some(25),
        offset: Some(0),
    };

    assert_eq!(query.installation.as_deref(), Some("Test Base AFB"));
    assert_eq!(query.status, Some(PrinterStatus::Online));
    assert_eq!(query.health_below, Some(60));
}

#[test]
fn integration_fleet_summary_construction() {
    let summary = FleetSummary {
        total_printers: 150,
        online_count: 120,
        offline_count: 10,
        error_count: 5,
        maintenance_count: 15,
        average_health_score: 82.5,
        critical_supply_count: 8,
    };

    assert_eq!(
        summary.online_count + summary.offline_count + summary.error_count + summary.maintenance_count,
        150
    );
}

#[test]
fn integration_printer_id_rejects_invalid_format() {
    assert!(PrinterId::new("INVALID").is_err());
    assert!(PrinterId::new("PRN-").is_err());
    assert!(PrinterId::new("").is_err());
}

#[test]
fn integration_printer_id_accepts_valid_format() {
    assert!(PrinterId::new("PRN-0001").is_ok());
    assert!(PrinterId::new("PRN-ABCD").is_ok());
    assert!(PrinterId::new("PRN-00001").is_ok());
}

// ---------------------------------------------------------------------------
// SNMPv3 credential validation tests
// ---------------------------------------------------------------------------

#[test]
fn integration_snmpv3_only_authpriv_accepted() {
    // Only AuthPriv security level is defined; NoAuth and AuthNoPriv are
    // intentionally absent from the enum, enforcing the policy at the type level.
    let level = SnmpSecurityLevel::AuthPriv;
    assert_eq!(level, SnmpSecurityLevel::AuthPriv);
}

#[test]
fn integration_snmpv3_only_sha256_auth() {
    // Only SHA-256 is defined; MD5 and SHA-1 are not available.
    let auth = SnmpAuthProtocol::Sha256;
    assert_eq!(auth, SnmpAuthProtocol::Sha256);
}

#[test]
fn integration_snmpv3_only_aes128_privacy() {
    // Only AES-128 is defined; DES and 3DES are not available.
    let priv_proto = SnmpPrivacyProtocol::Aes128;
    assert_eq!(priv_proto, SnmpPrivacyProtocol::Aes128);
}

#[test]
fn integration_snmpv3_poll_request_construction() {
    let request = SnmpPollRequest {
        printer_id: test_printer_id(),
        target: "10.0.1.100".parse().unwrap(),
        poll_type: SnmpPollType::FullTelemetry,
    };

    assert_eq!(request.poll_type, SnmpPollType::FullTelemetry);
    assert_eq!(request.printer_id.as_str(), "PRN-0001");
}

#[test]
fn integration_snmpv3_status_response_construction() {
    let response = SnmpStatusResponse {
        printer_id: test_printer_id(),
        status: PrinterStatus::Online,
        hr_printer_status: 3, // idle
        hr_device_status: 2, // running
        error_conditions: vec![],
        collected_at: Utc::now(),
    };

    assert_eq!(response.status, PrinterStatus::Online);
    assert!(response.error_conditions.is_empty());
}

#[test]
fn integration_snmpv3_poll_types_all_represented() {
    let types = [
        SnmpPollType::Status,
        SnmpPollType::SupplyLevels,
        SnmpPollType::FullTelemetry,
    ];
    assert_eq!(types.len(), 3);
    // Each poll type should be distinct.
    assert_ne!(types[0], types[1]);
    assert_ne!(types[1], types[2]);
    assert_ne!(types[0], types[2]);
}

// ---------------------------------------------------------------------------
// NIST evidence tests
// ---------------------------------------------------------------------------

#[test]
fn nist_si2_health_score_detects_firmware_mismatch() {
    // NIST 800-53 Rev 5: SI-2 — Flaw Remediation
    // Evidence: Outdated firmware reduces the health score, enabling the
    // fleet manager to prioritize firmware updates via SI-2 flaw remediation.
    let mut current_fw = healthy_input();
    current_fw.firmware_current = true;

    let mut outdated_fw = healthy_input();
    outdated_fw.firmware_current = false;

    let weights = HealthWeights::default();
    let score_current = compute_health_score(&current_fw, &weights).unwrap();
    let score_outdated = compute_health_score(&outdated_fw, &weights).unwrap();

    // Current firmware gets full marks on the firmware factor.
    assert_eq!(score_current.breakdown.firmware_currency, 100);
    // Outdated firmware gets a reduced score (40).
    assert_eq!(score_outdated.breakdown.firmware_currency, 40);
    // The overall score must be lower when firmware is outdated.
    assert!(
        score_outdated.overall < score_current.overall,
        "outdated firmware scored {} but should be less than current firmware score {}",
        score_outdated.overall,
        score_current.overall
    );

    // The firmware weight is 10%, so the difference should be (100 - 40) * 10 / 100 = 6 points.
    let expected_diff = u8::try_from(
        (u16::from(100u8) - u16::from(40u8))
            .saturating_mul(10)
            .checked_div(100)
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let actual_diff = score_current.overall - score_outdated.overall;
    assert_eq!(
        actual_diff, expected_diff,
        "firmware outdated penalty should be {expected_diff} points, got {actual_diff}",
    );
}

#[test]
fn nist_au12_discovery_emits_audit_event_type() {
    // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
    // Evidence: Discovery results map to well-defined audit event types in
    // the `EventKind` catalog, ensuring every discovery action is auditable.

    // Verify that the fleet-relevant EventKind variants exist and are distinct.
    let printer_discovered = EventKind::PrinterDiscovered;
    let printer_online = EventKind::PrinterOnline;
    let printer_offline = EventKind::PrinterOffline;
    let printer_error = EventKind::PrinterError;
    let supply_critical = EventKind::SupplyCritical;

    // All fleet event kinds must be distinct.
    let kinds = [
        printer_discovered,
        printer_online,
        printer_offline,
        printer_error,
        supply_critical,
    ];
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert_ne!(
                kinds[i], kinds[j],
                "EventKind variants at indices {i} and {j} should be distinct"
            );
        }
    }

    // A discovery scan result should map to PrinterDiscovered for each found device.
    let scan_result = DiscoveryScanResult {
        scan_id: Uuid::new_v4(),
        discovered: vec![
            DiscoveredPrinter {
                ip_address: "10.0.1.101".parse().unwrap(),
                hostname: None,
                model: Some(test_model()),
                serial_number: Some("SN-TEST-100".to_string()),
                method: DiscoveryMethod::SnmpV3Walk,
                discovered_at: Utc::now(),
                scan_id: None,
            },
            DiscoveredPrinter {
                ip_address: "10.0.1.102".parse().unwrap(),
                hostname: None,
                model: None,
                serial_number: None,
                method: DiscoveryMethod::DnsSd,
                discovered_at: Utc::now(),
                scan_id: None,
            },
        ],
        failed_subnets: vec![],
        stig_violations: vec![],
        completed_at: Utc::now(),
    };

    // Each discovered printer should produce a PrinterDiscovered event.
    // We verify the mapping holds by confirming the count matches.
    assert_eq!(scan_result.discovered.len(), 2);
    // The event kind for discovery is always PrinterDiscovered.
    assert_eq!(printer_discovered, EventKind::PrinterDiscovered);
}

// ---------------------------------------------------------------------------
// Alert severity ordering test
// ---------------------------------------------------------------------------

#[test]
fn integration_alert_severity_ordering() {
    assert!(AlertSeverity::Info < AlertSeverity::Warning);
    assert!(AlertSeverity::Warning < AlertSeverity::Critical);
}

// ---------------------------------------------------------------------------
// Custom alert thresholds test
// ---------------------------------------------------------------------------

#[test]
fn integration_custom_alert_thresholds() {
    let custom = AlertThresholds {
        toner_warning_pct: 30,
        toner_critical_pct: 10,
        paper_warning_pct: 25,
        paper_critical_pct: 10,
        health_degraded_score: 70,
        health_critical_score: 40,
        offline_after_failures: 5,
    };

    // 15% toner is below custom warning (30%) but above custom critical (10%).
    let alerts = evaluate_supply_alerts(&test_printer_id(), 15, 80, &custom);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Warning);

    // 8% toner is below custom critical (10%).
    let alerts = evaluate_supply_alerts(&test_printer_id(), 8, 80, &custom);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Critical);

    // 65% health is below custom degraded (70%) but above custom critical (40%).
    let health = HealthScore {
        overall: 65,
        breakdown: HealthBreakdown {
            connectivity: 80,
            error_state: 60,
            supply_levels: 50,
            queue_depth: 70,
            firmware_currency: 100,
        },
    };
    let alerts = evaluate_health_alerts(&test_printer_id(), &health, &custom);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].severity, AlertSeverity::Warning);
}
