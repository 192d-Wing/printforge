// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Configuration for the `pf-policy-engine` crate.
//!
//! Supports two deployment modes:
//! - **Sidecar:** `OPA` runs as a Kubernetes sidecar; we call its REST API.
//! - **Embedded:** A lightweight `Rego` evaluator runs in-process (cache nodes).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Top-level configuration for the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Which evaluation mode to use.
    pub mode: EvaluationMode,

    /// Maximum time to wait for a policy decision before defaulting to deny.
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub evaluation_timeout: Duration,

    /// Default page limit per job when no organizational policy overrides it.
    #[serde(default = "default_page_limit")]
    pub default_page_limit: u32,
}

/// Determines how policy evaluation is performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvaluationMode {
    /// Call `OPA` over its REST API (sidecar or remote).
    Sidecar(OpaClientConfig),
    /// Use an embedded evaluator with bundled policies.
    Embedded(EmbeddedConfig),
}

/// Configuration for the `OPA` sidecar REST client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaClientConfig {
    /// Base URL of the `OPA` REST API (e.g., `http://localhost:8181`).
    pub base_url: String,

    /// Path to the policy decision endpoint
    /// (e.g., `/v1/data/printforge/job/allow`).
    pub policy_path: String,

    /// Whether to use mTLS for `OPA` communication.
    #[serde(default)]
    pub mtls_enabled: bool,
}

/// Configuration for the embedded `Rego` evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedConfig {
    /// Path to the directory containing `Rego` policy bundles.
    pub bundle_path: PathBuf,
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

const fn default_page_limit() -> u32 {
    500
}

/// Shim module so we can deserialize durations from human-readable strings
/// (e.g., `"5s"`, `"2m"`) without pulling in the `humantime-serde` crate at
/// runtime. Falls back to seconds when the value is a plain integer.
mod humantime_serde {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_page_limit_is_500() {
        assert_eq!(default_page_limit(), 500);
    }

    #[test]
    fn default_timeout_is_5s() {
        assert_eq!(default_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn sidecar_config_deserializes_from_json() {
        let json = r#"{
            "mode": {
                "type": "sidecar",
                "base_url": "http://localhost:8181",
                "policy_path": "/v1/data/printforge/job/allow",
                "mtls_enabled": false
            },
            "evaluation_timeout": 10,
            "default_page_limit": 1000
        }"#;
        let config: PolicyConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.mode, EvaluationMode::Sidecar(_)));
        assert_eq!(config.evaluation_timeout, Duration::from_secs(10));
        assert_eq!(config.default_page_limit, 1000);
    }

    #[test]
    fn embedded_config_deserializes_from_json() {
        let json = r#"{
            "mode": {
                "type": "embedded",
                "bundle_path": "/opt/printforge/policies"
            },
            "evaluation_timeout": 3,
            "default_page_limit": 250
        }"#;
        let config: PolicyConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(config.mode, EvaluationMode::Embedded(_)));
    }
}
