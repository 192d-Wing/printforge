// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `NATS` leaf node connection management.
//!
//! Manages the connection to the central `NATS` cluster, buffering
//! outbound messages during disconnection and replaying them on
//! reconnect.
//!
//! **NIST 800-53 Rev 5:** SC-8 — Transmission Confidentiality
//! All `NATS` connections use TLS with mTLS.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CacheNodeError;

/// Maximum buffer size in bytes for outbound messages during disconnection.
const DEFAULT_MAX_BUFFER_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Connection state of the `NATS` leaf node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeafConnectionState {
    /// Connected to the central `NATS` cluster.
    Connected,
    /// Disconnected; buffering outbound messages.
    Disconnected,
    /// Reconnecting; replaying buffered messages.
    Reconnecting,
}

/// A message buffered during `NATS` disconnection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedMessage {
    /// The `NATS` subject to publish to.
    pub subject: String,
    /// The message payload.
    pub payload: Vec<u8>,
    /// When the message was originally produced.
    pub buffered_at: DateTime<Utc>,
}

/// Manages `NATS` leaf node state and message buffering.
#[derive(Debug)]
pub struct NatsLeafNode {
    /// Current connection state.
    state: LeafConnectionState,
    /// Outbound message buffer used during disconnection.
    buffer: VecDeque<BufferedMessage>,
    /// Current total size of buffered message payloads in bytes.
    buffer_bytes: u64,
    /// Maximum buffer size in bytes.
    max_buffer_bytes: u64,
    /// Timestamp of the last successful connection.
    last_connected: Option<DateTime<Utc>>,
    /// Number of messages replayed on the last reconnect.
    last_replay_count: u64,
}

impl NatsLeafNode {
    /// Create a new `NatsLeafNode` with default buffer settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: LeafConnectionState::Disconnected,
            buffer: VecDeque::new(),
            buffer_bytes: 0,
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            last_connected: None,
            last_replay_count: 0,
        }
    }

    /// Create a new `NatsLeafNode` with a custom max buffer size.
    #[must_use]
    pub fn with_max_buffer(max_buffer_bytes: u64) -> Self {
        Self {
            max_buffer_bytes,
            ..Self::new()
        }
    }

    /// Return the current connection state.
    #[must_use]
    pub fn state(&self) -> LeafConnectionState {
        self.state
    }

    /// Return the number of buffered messages.
    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Return the total size of buffered message payloads in bytes.
    #[must_use]
    pub fn buffered_bytes(&self) -> u64 {
        self.buffer_bytes
    }

    /// Return the timestamp of the last successful connection, if any.
    #[must_use]
    pub fn last_connected(&self) -> Option<DateTime<Utc>> {
        self.last_connected
    }

    /// Return the number of messages replayed on the last reconnect.
    #[must_use]
    pub fn last_replay_count(&self) -> u64 {
        self.last_replay_count
    }

    /// Mark the leaf node as connected to the central `NATS` cluster.
    pub fn mark_connected(&mut self) {
        self.state = LeafConnectionState::Connected;
        self.last_connected = Some(Utc::now());
        tracing::info!("NATS leaf node connected to central cluster");
    }

    /// Mark the leaf node as disconnected and begin buffering.
    pub fn mark_disconnected(&mut self) {
        self.state = LeafConnectionState::Disconnected;
        tracing::warn!("NATS leaf node disconnected from central cluster");
    }

    /// Buffer an outbound message during disconnection.
    ///
    /// # Errors
    ///
    /// Returns `CacheNodeError::Nats` if the buffer is full (exceeds
    /// the configured maximum buffer size).
    pub fn buffer_message(
        &mut self,
        subject: String,
        payload: Vec<u8>,
    ) -> Result<(), CacheNodeError> {
        let payload_len = payload.len() as u64;
        if self.buffer_bytes + payload_len > self.max_buffer_bytes {
            return Err(CacheNodeError::Nats {
                message: format!(
                    "buffer full: {} + {} > {} bytes",
                    self.buffer_bytes, payload_len, self.max_buffer_bytes
                ),
            });
        }

        self.buffer.push_back(BufferedMessage {
            subject,
            payload,
            buffered_at: Utc::now(),
        });
        self.buffer_bytes += payload_len;

        tracing::debug!(
            buffered_count = self.buffer.len(),
            buffered_bytes = self.buffer_bytes,
            "message buffered"
        );
        Ok(())
    }

    /// Drain all buffered messages for replay on reconnect.
    /// Returns the messages in FIFO order and resets the buffer.
    pub fn drain_buffer(&mut self) -> Vec<BufferedMessage> {
        self.state = LeafConnectionState::Reconnecting;
        let messages: Vec<BufferedMessage> = self.buffer.drain(..).collect();
        self.last_replay_count = messages.len() as u64;
        self.buffer_bytes = 0;

        tracing::info!(
            replay_count = messages.len(),
            "draining NATS buffer for replay"
        );
        messages
    }
}

impl Default for NatsLeafNode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_leaf_node_is_disconnected() {
        let node = NatsLeafNode::new();
        assert_eq!(node.state(), LeafConnectionState::Disconnected);
        assert_eq!(node.buffered_count(), 0);
    }

    #[test]
    fn mark_connected_updates_state() {
        let mut node = NatsLeafNode::new();
        node.mark_connected();
        assert_eq!(node.state(), LeafConnectionState::Connected);
        assert!(node.last_connected().is_some());
    }

    #[test]
    fn buffer_message_increments_count_and_bytes() {
        let mut node = NatsLeafNode::new();
        node.buffer_message("test.subject".to_string(), vec![1, 2, 3])
            .unwrap();
        assert_eq!(node.buffered_count(), 1);
        assert_eq!(node.buffered_bytes(), 3);
    }

    #[test]
    fn buffer_rejects_when_full() {
        let mut node = NatsLeafNode::with_max_buffer(5);
        node.buffer_message("a".to_string(), vec![1, 2, 3]).unwrap();
        let result = node.buffer_message("b".to_string(), vec![4, 5, 6]);
        assert!(result.is_err());
    }

    #[test]
    fn drain_buffer_returns_fifo_order() {
        let mut node = NatsLeafNode::new();
        node.buffer_message("first".to_string(), vec![1]).unwrap();
        node.buffer_message("second".to_string(), vec![2]).unwrap();
        let messages = node.drain_buffer();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].subject, "first");
        assert_eq!(messages[1].subject, "second");
        assert_eq!(node.buffered_count(), 0);
        assert_eq!(node.buffered_bytes(), 0);
    }

    #[test]
    fn drain_sets_reconnecting_state() {
        let mut node = NatsLeafNode::new();
        node.buffer_message("test".to_string(), vec![1]).unwrap();
        node.drain_buffer();
        assert_eq!(node.state(), LeafConnectionState::Reconnecting);
    }

    #[test]
    fn nist_sc8_default_buffer_is_256mib() {
        let node = NatsLeafNode::new();
        assert_eq!(node.max_buffer_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn last_replay_count_tracks_drain() {
        let mut node = NatsLeafNode::new();
        node.buffer_message("a".to_string(), vec![1]).unwrap();
        node.buffer_message("b".to_string(), vec![2]).unwrap();
        node.drain_buffer();
        assert_eq!(node.last_replay_count(), 2);
    }
}
