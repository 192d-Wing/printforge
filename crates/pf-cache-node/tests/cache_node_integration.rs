// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Integration tests for the `pf-cache-node` crate.
//!
//! Covers mode transitions, vector clock sync, heartbeat monitoring,
//! NATS leaf buffering, and auth cache behavior.

use std::time::Duration;

use chrono::Utc;
use pf_cache_node::auth_cache::{AuthCache, CacheLookup, CachedOcspResponse};
use pf_cache_node::config::{AuthCacheConfig, HeartbeatConfig};
use pf_cache_node::error::DdilReason;
use pf_cache_node::heartbeat::{HeartbeatMonitor, HeartbeatPayload};
use pf_cache_node::mode::{validate_transition, ModeState, OperatingMode};
use pf_cache_node::nats_leaf::{LeafConnectionState, NatsLeafNode};
use pf_cache_node::sync::{ClockOrdering, SyncDelta, SyncOutcome, VectorClock};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// 1. Mode transition tests
// ---------------------------------------------------------------------------

/// NIST 800-53 Rev 5: AC-3 — Access Enforcement
/// Evidence: Connected -> Degraded is a valid state transition triggered
/// by a single heartbeat failure.
#[test]
fn nist_ac3_connected_to_degraded_transition() {
    let mut state = ModeState::new(1, 3);
    assert_eq!(state.current(), OperatingMode::Connected);

    let transition = state.heartbeat_failure().unwrap();
    assert!(transition.is_some(), "expected a mode transition");

    let t = transition.unwrap();
    assert_eq!(t.from, OperatingMode::Connected);
    assert_eq!(t.to, OperatingMode::Degraded);
    assert_eq!(state.current(), OperatingMode::Degraded);
    assert_eq!(state.consecutive_failures(), 1);
}

/// NIST 800-53 Rev 5: AC-3 — Access Enforcement
/// Evidence: Degraded -> DDIL is a valid state transition triggered
/// when consecutive heartbeat failures reach the DDIL threshold.
#[test]
fn nist_ac3_degraded_to_ddil_transition() {
    let mut state = ModeState::new(1, 3);

    // First failure: Connected -> Degraded
    state.heartbeat_failure().unwrap();
    assert_eq!(state.current(), OperatingMode::Degraded);

    // Second failure: still Degraded
    state.heartbeat_failure().unwrap();
    assert_eq!(state.current(), OperatingMode::Degraded);

    // Third failure: Degraded -> DDIL
    let transition = state.heartbeat_failure().unwrap();
    assert!(transition.is_some(), "expected DDIL transition");

    let t = transition.unwrap();
    assert_eq!(t.from, OperatingMode::Degraded);
    assert_eq!(t.to, OperatingMode::Ddil);
    assert_eq!(state.current(), OperatingMode::Ddil);

    // Verify the reason is recorded
    assert!(t.reason.is_some());
    if let Some(DdilReason::HeartbeatTimeout {
        consecutive_failures,
    }) = t.reason
    {
        assert_eq!(consecutive_failures, 3);
    } else {
        panic!("expected HeartbeatTimeout reason");
    }
}

/// NIST 800-53 Rev 5: AC-3 — Access Enforcement
/// Evidence: DDIL -> Connected is the recovery path triggered by a
/// successful heartbeat after DDIL mode.
#[test]
fn nist_ac3_ddil_to_connected_transition() {
    let mut state = ModeState::new(1, 3);

    // Drive into DDIL
    for _ in 0..3 {
        state.heartbeat_failure().unwrap();
    }
    assert_eq!(state.current(), OperatingMode::Ddil);

    // Recovery
    let transition = state.heartbeat_success().unwrap();
    assert!(transition.is_some(), "expected recovery transition");

    let t = transition.unwrap();
    assert_eq!(t.from, OperatingMode::Ddil);
    assert_eq!(t.to, OperatingMode::Connected);
    assert_eq!(state.current(), OperatingMode::Connected);
    assert_eq!(state.consecutive_failures(), 0);
}

/// NIST 800-53 Rev 5: AC-3 — Access Enforcement
/// Evidence: DDIL -> Degraded is an invalid transition. The only valid
/// exit from DDIL is directly to Connected (full reconnect required).
#[test]
fn nist_ac3_ddil_to_degraded_is_rejected() {
    let result = validate_transition(OperatingMode::Ddil, OperatingMode::Degraded);
    assert!(result.is_err(), "DDIL -> Degraded should be rejected");
}

/// Connected -> DDIL is allowed as a manual override path.
/// Verify via the `validate_transition` function.
#[test]
fn integration_connected_to_ddil_manual_override_allowed() {
    let result = validate_transition(OperatingMode::Connected, OperatingMode::Ddil);
    assert!(result.is_ok(), "Connected -> DDIL (manual override) should be valid");
}

/// All transitions are recorded in the audit trail.
#[test]
fn integration_mode_transitions_are_auditable() {
    let mut state = ModeState::new(1, 3);

    // Connected -> Degraded -> DDIL -> Connected
    state.heartbeat_failure().unwrap(); // -> Degraded
    state.heartbeat_failure().unwrap(); // still Degraded (no transition)
    state.heartbeat_failure().unwrap(); // -> DDIL
    state.heartbeat_success().unwrap(); // -> Connected

    let transitions = state.transitions();
    assert_eq!(transitions.len(), 3);
    assert_eq!(transitions[0].from, OperatingMode::Connected);
    assert_eq!(transitions[0].to, OperatingMode::Degraded);
    assert_eq!(transitions[1].from, OperatingMode::Degraded);
    assert_eq!(transitions[1].to, OperatingMode::Ddil);
    assert_eq!(transitions[2].from, OperatingMode::Ddil);
    assert_eq!(transitions[2].to, OperatingMode::Connected);
}

// ---------------------------------------------------------------------------
// 2. Vector clock sync tests
// ---------------------------------------------------------------------------

/// Two clocks with no common events report Concurrent ordering.
#[test]
fn integration_vector_clocks_no_common_events_are_concurrent() {
    let mut clock_a = VectorClock::new();
    clock_a.increment("node-alpha");

    let mut clock_b = VectorClock::new();
    clock_b.increment("node-beta");

    assert_eq!(clock_a.compare(&clock_b), ClockOrdering::Concurrent);
    assert_eq!(clock_b.compare(&clock_a), ClockOrdering::Concurrent);
}

/// Clock increment produces Before/After ordering correctly.
#[test]
fn integration_vector_clock_increment_produces_ordering() {
    let mut clock_v1 = VectorClock::new();
    clock_v1.increment("node-a");

    let mut clock_v2 = clock_v1.clone();
    clock_v2.increment("node-a");

    // v1 happened before v2
    assert_eq!(clock_v1.compare(&clock_v2), ClockOrdering::Before);
    // v2 happened after v1
    assert_eq!(clock_v2.compare(&clock_v1), ClockOrdering::After);
}

/// Delta records preserve causal ordering through the vector clock.
#[test]
fn integration_sync_delta_preserves_causal_ordering() {
    let job_id = Uuid::now_v7();

    // Simulate: local creates job, then central modifies it
    let mut local_clock = VectorClock::new();
    local_clock.increment("edge-site-001");

    let mut central_clock = local_clock.clone();
    central_clock.increment("central");

    let local_delta = SyncDelta {
        job_id,
        clock: local_clock,
        payload: b"local-v1".to_vec(),
        modified_at: Utc::now(),
        origin_node: "edge-site-001".to_string(),
    };

    let central_delta = SyncDelta {
        job_id,
        clock: central_clock,
        payload: b"central-v2".to_vec(),
        modified_at: Utc::now(),
        origin_node: "central".to_string(),
    };

    // Central's clock is strictly after local's
    let outcome = pf_cache_node::sync::resolve_conflict(&local_delta, &central_delta).unwrap();
    assert_eq!(outcome, SyncOutcome::CentralWins);
}

/// Merge of concurrent updates uses deterministic tiebreaker (central wins).
#[test]
fn integration_sync_concurrent_merge_central_wins() {
    let job_id = Uuid::now_v7();

    // Both nodes independently modify the same job
    let mut local_clock = VectorClock::new();
    local_clock.increment("edge-site-001");
    local_clock.increment("edge-site-001");

    let mut central_clock = VectorClock::new();
    central_clock.increment("central");
    central_clock.increment("central");

    let local_delta = SyncDelta {
        job_id,
        clock: local_clock.clone(),
        payload: b"local-modification".to_vec(),
        modified_at: Utc::now(),
        origin_node: "edge-site-001".to_string(),
    };

    let central_delta = SyncDelta {
        job_id,
        clock: central_clock.clone(),
        payload: b"central-modification".to_vec(),
        modified_at: Utc::now(),
        origin_node: "central".to_string(),
    };

    // Clocks are concurrent
    assert_eq!(local_clock.compare(&central_clock), ClockOrdering::Concurrent);

    // resolve_conflict returns SyncConflict error, indicating central wins
    let result = pf_cache_node::sync::resolve_conflict(&local_delta, &central_delta);
    assert!(result.is_err(), "concurrent modifications should produce SyncConflict");
}

/// Merging two clocks takes the max of each node entry.
#[test]
fn integration_vector_clock_merge_takes_max() {
    let mut clock_a = VectorClock::new();
    clock_a.increment("node-a");
    clock_a.increment("node-a"); // node-a: 2
    clock_a.increment("node-b"); // node-b: 1

    let mut clock_b = VectorClock::new();
    clock_b.increment("node-a"); // node-a: 1
    clock_b.increment("node-b");
    clock_b.increment("node-b");
    clock_b.increment("node-b"); // node-b: 3
    clock_b.increment("node-c"); // node-c: 1

    clock_a.merge(&clock_b);

    assert_eq!(clock_a.entries["node-a"], 2); // max(2, 1) = 2
    assert_eq!(clock_a.entries["node-b"], 3); // max(1, 3) = 3
    assert_eq!(clock_a.entries["node-c"], 1); // max(0, 1) = 1
}

// ---------------------------------------------------------------------------
// 3. Heartbeat monitoring tests
// ---------------------------------------------------------------------------

/// Heartbeat payload construction with correct node ID and timestamp.
#[test]
fn integration_heartbeat_payload_construction() {
    let now = Utc::now();
    let payload = HeartbeatPayload {
        site_id: "TESTSITE-001".to_string(),
        mode: OperatingMode::Connected,
        local_queue_depth: 15,
        reachable_printers: 8,
        timestamp: now,
    };

    assert_eq!(payload.site_id, "TESTSITE-001");
    assert_eq!(payload.mode, OperatingMode::Connected);
    assert_eq!(payload.local_queue_depth, 15);
    assert_eq!(payload.reachable_printers, 8);
    assert_eq!(payload.timestamp, now);

    // Verify JSON round-trip preserves all fields
    let json = serde_json::to_string(&payload).unwrap();
    let deserialized: HeartbeatPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.site_id, "TESTSITE-001");
    assert_eq!(deserialized.local_queue_depth, 15);
    assert_eq!(deserialized.reachable_printers, 8);
}

/// Failure count tracks consecutive misses correctly.
#[test]
fn integration_heartbeat_failure_count_tracks_consecutive_misses() {
    let mut monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
    let mut mode_state = ModeState::new(1, 3);

    // Record two consecutive failures
    monitor.record_failure(&mut mode_state).unwrap();
    assert_eq!(mode_state.consecutive_failures(), 1);

    monitor.record_failure(&mut mode_state).unwrap();
    assert_eq!(mode_state.consecutive_failures(), 2);

    // Success resets the counter
    monitor.record_success(&mut mode_state).unwrap();
    assert_eq!(mode_state.consecutive_failures(), 0);

    // Failures start counting again from zero
    monitor.record_failure(&mut mode_state).unwrap();
    assert_eq!(mode_state.consecutive_failures(), 1);
}

/// Threshold crossing triggers mode transition signal.
#[test]
fn integration_heartbeat_threshold_crossing_triggers_transition() {
    let mut monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
    let mut mode_state = ModeState::new(1, 3);

    // First failure: should trigger Degraded transition
    let transition = monitor.record_failure(&mut mode_state).unwrap();
    assert!(transition.is_some());
    assert_eq!(mode_state.current(), OperatingMode::Degraded);

    // Second failure: no new transition (still Degraded)
    let transition = monitor.record_failure(&mut mode_state).unwrap();
    assert!(transition.is_none());
    assert_eq!(mode_state.current(), OperatingMode::Degraded);

    // Third failure: should trigger DDIL transition
    let transition = monitor.record_failure(&mut mode_state).unwrap();
    assert!(transition.is_some());
    assert_eq!(mode_state.current(), OperatingMode::Ddil);
}

/// Heartbeat monitor records timestamps on success and failure.
#[test]
fn integration_heartbeat_timestamps_recorded() {
    let mut monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
    let mut mode_state = ModeState::new(1, 3);

    assert!(monitor.last_attempt().is_none());
    assert!(monitor.last_success().is_none());

    monitor.record_failure(&mut mode_state).unwrap();
    assert!(monitor.last_attempt().is_some());
    assert!(monitor.last_success().is_none());

    monitor.record_success(&mut mode_state).unwrap();
    assert!(monitor.last_attempt().is_some());
    assert!(monitor.last_success().is_some());
}

// ---------------------------------------------------------------------------
// 4. NATS leaf buffering tests
// ---------------------------------------------------------------------------

/// Messages are buffered during disconnect.
#[test]
fn integration_nats_messages_buffered_during_disconnect() {
    let mut leaf = NatsLeafNode::new();
    // Node starts disconnected by default
    assert_eq!(leaf.state(), LeafConnectionState::Disconnected);

    leaf.buffer_message("print.job.submit".to_string(), b"job-payload-1".to_vec())
        .unwrap();
    leaf.buffer_message("print.job.submit".to_string(), b"job-payload-2".to_vec())
        .unwrap();
    leaf.buffer_message("fleet.status".to_string(), b"status-payload".to_vec())
        .unwrap();

    assert_eq!(leaf.buffered_count(), 3);
}

/// Buffer size tracking is accurate.
#[test]
fn integration_nats_buffer_size_tracking_accurate() {
    let mut leaf = NatsLeafNode::new();

    let payload_a = vec![0u8; 100];
    let payload_b = vec![0u8; 250];
    let payload_c = vec![0u8; 50];

    leaf.buffer_message("a".to_string(), payload_a).unwrap();
    assert_eq!(leaf.buffered_bytes(), 100);

    leaf.buffer_message("b".to_string(), payload_b).unwrap();
    assert_eq!(leaf.buffered_bytes(), 350);

    leaf.buffer_message("c".to_string(), payload_c).unwrap();
    assert_eq!(leaf.buffered_bytes(), 400);

    assert_eq!(leaf.buffered_count(), 3);
}

/// Buffer replay ordering preserved (FIFO).
#[test]
fn integration_nats_buffer_replay_ordering_preserved() {
    let mut leaf = NatsLeafNode::new();

    leaf.buffer_message("first".to_string(), b"1".to_vec()).unwrap();
    leaf.buffer_message("second".to_string(), b"2".to_vec()).unwrap();
    leaf.buffer_message("third".to_string(), b"3".to_vec()).unwrap();

    let messages = leaf.drain_buffer();

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].subject, "first");
    assert_eq!(messages[0].payload, b"1");
    assert_eq!(messages[1].subject, "second");
    assert_eq!(messages[1].payload, b"2");
    assert_eq!(messages[2].subject, "third");
    assert_eq!(messages[2].payload, b"3");

    // After drain, buffer is empty and state is Reconnecting
    assert_eq!(leaf.buffered_count(), 0);
    assert_eq!(leaf.buffered_bytes(), 0);
    assert_eq!(leaf.state(), LeafConnectionState::Reconnecting);
    assert_eq!(leaf.last_replay_count(), 3);
}

/// Buffer rejects messages when capacity is exceeded.
#[test]
fn integration_nats_buffer_rejects_when_full() {
    let mut leaf = NatsLeafNode::with_max_buffer(10);

    leaf.buffer_message("ok".to_string(), vec![0u8; 8]).unwrap();
    assert_eq!(leaf.buffered_bytes(), 8);

    // This would push us to 8 + 5 = 13 > 10
    let result = leaf.buffer_message("overflow".to_string(), vec![0u8; 5]);
    assert!(result.is_err(), "should reject when buffer would overflow");

    // Original message remains
    assert_eq!(leaf.buffered_count(), 1);
    assert_eq!(leaf.buffered_bytes(), 8);
}

/// Connected -> Disconnected -> buffer -> drain -> reconnect lifecycle.
#[test]
fn integration_nats_full_disconnect_reconnect_lifecycle() {
    let mut leaf = NatsLeafNode::new();

    // Start connected
    leaf.mark_connected();
    assert_eq!(leaf.state(), LeafConnectionState::Connected);
    assert!(leaf.last_connected().is_some());

    // Disconnect occurs
    leaf.mark_disconnected();
    assert_eq!(leaf.state(), LeafConnectionState::Disconnected);

    // Buffer messages while disconnected
    leaf.buffer_message("queued.1".to_string(), b"data-1".to_vec()).unwrap();
    leaf.buffer_message("queued.2".to_string(), b"data-2".to_vec()).unwrap();

    // Drain for replay
    let replayed = leaf.drain_buffer();
    assert_eq!(replayed.len(), 2);
    assert_eq!(leaf.state(), LeafConnectionState::Reconnecting);

    // Reconnect completes
    leaf.mark_connected();
    assert_eq!(leaf.state(), LeafConnectionState::Connected);
}

// ---------------------------------------------------------------------------
// 5. Auth cache tests
// ---------------------------------------------------------------------------

/// Helper: create a valid (non-expired) OCSP response with the given serial.
fn make_valid_ocsp(serial: &str) -> CachedOcspResponse {
    CachedOcspResponse {
        cert_serial: serial.to_string(),
        is_valid: true,
        fetched_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(4),
        response_hash: format!("sha256:test-hash-{serial}"),
    }
}

/// Helper: create an already-expired OCSP response with the given serial.
fn make_expired_ocsp(serial: &str) -> CachedOcspResponse {
    CachedOcspResponse {
        cert_serial: serial.to_string(),
        is_valid: true,
        fetched_at: Utc::now() - chrono::Duration::hours(5),
        expires_at: Utc::now() - chrono::Duration::hours(1),
        response_hash: format!("sha256:expired-hash-{serial}"),
    }
}

/// NIST 800-53 Rev 5: IA-5(2) — Cached OCSP response is returned within TTL.
#[test]
fn nist_ia5_2_cached_ocsp_response_returned_within_ttl() {
    let config = AuthCacheConfig {
        ttl: Duration::from_secs(4 * 3600),
        max_entries: 100,
    };
    let mut cache = AuthCache::new(&config);

    let response = make_valid_ocsp("SERIAL-001");
    cache.store_ocsp(response).unwrap();

    let result = cache.lookup_ocsp("SERIAL-001");
    match result {
        CacheLookup::Hit(entry) => {
            assert_eq!(entry.cert_serial, "SERIAL-001");
            assert!(entry.is_valid);
            assert!(!entry.is_expired());
        }
        other => panic!("expected CacheLookup::Hit, got {other:?}"),
    }

    assert_eq!(cache.hit_count(), 1);
    assert_eq!(cache.miss_count(), 0);
}

/// NIST 800-53 Rev 5: IA-5(2) — Expired cache entry triggers refresh
/// (returns Expired, not Hit).
#[test]
fn nist_ia5_2_expired_cache_entry_triggers_refresh() {
    let config = AuthCacheConfig {
        ttl: Duration::from_secs(4 * 3600),
        max_entries: 100,
    };
    let mut cache = AuthCache::new(&config);

    let response = make_expired_ocsp("EXPIRED-SERIAL");
    cache.store_ocsp(response).unwrap();

    let result = cache.lookup_ocsp("EXPIRED-SERIAL");
    assert!(
        matches!(result, CacheLookup::Expired),
        "expired OCSP entry should return Expired, not Hit"
    );

    // Expired lookups count as misses
    assert_eq!(cache.miss_count(), 1);
    assert_eq!(cache.hit_count(), 0);
}

/// Cache miss for unknown serial returns Miss.
#[test]
fn integration_auth_cache_miss_for_unknown_serial() {
    let config = AuthCacheConfig {
        ttl: Duration::from_secs(3600),
        max_entries: 100,
    };
    let mut cache = AuthCache::new(&config);

    let result = cache.lookup_ocsp("NONEXISTENT-SERIAL");
    assert!(matches!(result, CacheLookup::Miss));
    assert_eq!(cache.miss_count(), 1);
}

/// Cache hit rate is computed correctly over multiple lookups.
#[test]
fn integration_auth_cache_hit_rate_accuracy() {
    let config = AuthCacheConfig {
        ttl: Duration::from_secs(3600),
        max_entries: 100,
    };
    let mut cache = AuthCache::new(&config);

    cache.store_ocsp(make_valid_ocsp("A")).unwrap();
    cache.store_ocsp(make_valid_ocsp("B")).unwrap();

    // 2 hits
    cache.lookup_ocsp("A");
    cache.lookup_ocsp("B");
    // 2 misses
    cache.lookup_ocsp("X");
    cache.lookup_ocsp("Y");

    assert_eq!(cache.hit_count(), 2);
    assert_eq!(cache.miss_count(), 2);
    assert!((cache.hit_rate() - 0.5).abs() < f64::EPSILON);
}

/// Cache rejects new entries when at capacity.
#[test]
fn integration_auth_cache_capacity_enforcement() {
    let config = AuthCacheConfig {
        ttl: Duration::from_secs(3600),
        max_entries: 2,
    };
    let mut cache = AuthCache::new(&config);

    cache.store_ocsp(make_valid_ocsp("S1")).unwrap();
    cache.store_ocsp(make_valid_ocsp("S2")).unwrap();

    let result = cache.store_ocsp(make_valid_ocsp("S3"));
    assert!(result.is_err(), "cache should reject when at capacity");
}
