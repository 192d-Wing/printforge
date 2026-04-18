// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `OPA` REST client for policy evaluation.
//!
//! Communicates with an `OPA` sidecar over HTTP(S) to evaluate print-job
//! policies. When the sidecar is unreachable, the default-deny pattern
//! ensures the job is held.
//!
//! **NIST 800-53 Rev 5:** AC-3 — Access Enforcement, CM-7 — Least Functionality

use serde::{Deserialize, Serialize};

use pf_common::policy::PolicyDecision;

use crate::config::OpaClientConfig;
use crate::error::PolicyError;
use crate::input::PolicyInput;

/// Request body sent to the `OPA` `/v1/data/...` endpoint.
#[derive(Debug, Serialize)]
pub struct OpaRequest<'a> {
    /// The input document that `Rego` policies evaluate against.
    pub input: &'a PolicyInput,
}

/// Response body returned by `OPA` for a data query.
#[derive(Debug, Deserialize)]
pub struct OpaResponse {
    /// The policy decision result from the `Rego` evaluation.
    pub result: Option<OpaResult>,
}

/// The structured result extracted from the `OPA` response.
#[derive(Debug, Deserialize)]
pub struct OpaResult {
    /// Whether the job is allowed.
    #[serde(default)]
    pub allow: bool,
    /// If denied, the violation code (e.g., `"quota_exceeded"`).
    pub violation: Option<String>,
    /// If allowed with modification, the reason string.
    pub modification: Option<String>,
}

impl OpaResult {
    /// Convert the raw `OPA` result into a [`PolicyDecision`].
    #[must_use]
    pub fn into_decision(self) -> PolicyDecision {
        if self.allow {
            if let Some(reason) = self.modification {
                PolicyDecision::AllowWithModification { reason }
            } else {
                PolicyDecision::Allow
            }
        } else {
            let violation = self.violation.as_deref().map_or(
                pf_common::policy::PolicyViolation::Custom {
                    rule: "unknown".to_string(),
                    message: "policy denied the request".to_string(),
                },
                violation_from_code,
            );
            PolicyDecision::Deny(violation)
        }
    }
}

/// Map well-known violation codes from `Rego` to [`PolicyViolation`] variants.
fn violation_from_code(code: &str) -> pf_common::policy::PolicyViolation {
    use pf_common::policy::PolicyViolation;
    match code {
        "quota_exceeded" => PolicyViolation::QuotaExceeded,
        "color_not_allowed" => PolicyViolation::ColorNotAllowed,
        "printer_not_authorized" => PolicyViolation::PrinterNotAuthorized,
        other => PolicyViolation::Custom {
            rule: other.to_string(),
            message: "policy denied the request".to_string(),
        },
    }
}

/// An `OPA` REST client that can evaluate policy inputs.
///
/// This client is designed to be used with the `OPA` sidecar deployment
/// pattern. For embedded evaluation, see [`crate::embedded`].
#[derive(Debug, Clone)]
pub struct OpaClient {
    config: OpaClientConfig,
}

impl OpaClient {
    /// Create a new `OPA` client from the given configuration.
    #[must_use]
    pub fn new(config: OpaClientConfig) -> Self {
        Self { config }
    }

    /// Return the full URL for the policy evaluation endpoint.
    #[must_use]
    pub fn evaluation_url(&self) -> String {
        format!(
            "{}{}",
            self.config.base_url.trim_end_matches('/'),
            self.config.policy_path
        )
    }

    /// Evaluate a policy input against the `OPA` sidecar.
    ///
    /// In the current implementation this builds the request payload and
    /// parses the response. The actual HTTP transport is delegated to the
    /// caller (e.g., an Axum middleware or integration test harness) via
    /// [`evaluate_raw_response`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InputValidation`] if the input is invalid.
    pub fn build_request_body(&self, input: &PolicyInput) -> Result<String, PolicyError> {
        input.validate()?;
        let request = OpaRequest { input };
        serde_json::to_string(&request).map_err(|e| {
            PolicyError::InvalidResponse(format!("failed to serialize OPA request: {e}"))
        })
    }

    /// Parse a raw JSON response from `OPA` into a [`PolicyDecision`].
    ///
    /// **Default-deny:** If the response cannot be parsed, the job is denied.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidResponse`] if the JSON is malformed.
    pub fn parse_response(&self, raw_json: &str) -> Result<PolicyDecision, PolicyError> {
        let response: OpaResponse = serde_json::from_str(raw_json).map_err(|e| {
            PolicyError::InvalidResponse(format!("failed to parse OPA response: {e}"))
        })?;

        let result = response.result.ok_or_else(|| {
            PolicyError::InvalidResponse("OPA response missing 'result' field".to_string())
        })?;

        Ok(result.into_decision())
    }

    /// Return a reference to the underlying configuration.
    #[must_use]
    pub fn config(&self) -> &OpaClientConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opa_result_allow_maps_to_allow() {
        let result = OpaResult {
            allow: true,
            violation: None,
            modification: None,
        };
        assert_eq!(result.into_decision(), PolicyDecision::Allow);
    }

    #[test]
    fn opa_result_allow_with_modification() {
        let result = OpaResult {
            allow: true,
            violation: None,
            modification: Some("forced duplex".to_string()),
        };
        assert_eq!(
            result.into_decision(),
            PolicyDecision::AllowWithModification {
                reason: "forced duplex".to_string()
            }
        );
    }

    #[test]
    fn opa_result_deny_quota_exceeded() {
        let result = OpaResult {
            allow: false,
            violation: Some("quota_exceeded".to_string()),
            modification: None,
        };
        assert_eq!(
            result.into_decision(),
            PolicyDecision::Deny(pf_common::policy::PolicyViolation::QuotaExceeded)
        );
    }

    #[test]
    fn opa_result_deny_unknown_code_maps_to_custom() {
        let result = OpaResult {
            allow: false,
            violation: Some("some_new_rule".to_string()),
            modification: None,
        };
        let decision = result.into_decision();
        assert!(matches!(
            decision,
            PolicyDecision::Deny(pf_common::policy::PolicyViolation::Custom { .. })
        ));
    }

    #[test]
    fn opa_result_deny_no_violation_maps_to_custom() {
        let result = OpaResult {
            allow: false,
            violation: None,
            modification: None,
        };
        let decision = result.into_decision();
        assert!(matches!(
            decision,
            PolicyDecision::Deny(pf_common::policy::PolicyViolation::Custom { .. })
        ));
    }

    #[test]
    fn evaluation_url_trims_trailing_slash() {
        let client = OpaClient::new(OpaClientConfig {
            base_url: "http://localhost:8181/".to_string(),
            policy_path: "/v1/data/printforge/job/allow".to_string(),
            mtls_enabled: false,
        });
        assert_eq!(
            client.evaluation_url(),
            "http://localhost:8181/v1/data/printforge/job/allow"
        );
    }

    #[test]
    fn parse_response_allow() {
        let client = OpaClient::new(OpaClientConfig {
            base_url: "http://localhost:8181".to_string(),
            policy_path: "/v1/data/printforge/job/allow".to_string(),
            mtls_enabled: false,
        });
        let json = r#"{"result":{"allow":true}}"#;
        let decision = client.parse_response(json).unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn parse_response_deny() {
        let client = OpaClient::new(OpaClientConfig {
            base_url: "http://localhost:8181".to_string(),
            policy_path: "/v1/data/printforge/job/allow".to_string(),
            mtls_enabled: false,
        });
        let json = r#"{"result":{"allow":false,"violation":"color_not_allowed"}}"#;
        let decision = client.parse_response(json).unwrap();
        assert_eq!(
            decision,
            PolicyDecision::Deny(pf_common::policy::PolicyViolation::ColorNotAllowed)
        );
    }

    #[test]
    fn parse_response_missing_result_is_error() {
        let client = OpaClient::new(OpaClientConfig {
            base_url: "http://localhost:8181".to_string(),
            policy_path: "/v1/data/printforge/job/allow".to_string(),
            mtls_enabled: false,
        });
        let json = "{}";
        assert!(client.parse_response(json).is_err());
    }
}
