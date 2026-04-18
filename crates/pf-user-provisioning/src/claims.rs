// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Claims extraction and normalization from OIDC and SAML identity tokens.
//!
//! **NIST 800-53 Rev 5:** IA-2 — Identification and Authentication
//!
//! OIDC and SAML tokens carry user attributes in different structures.
//! This module normalizes both into a unified [`NormalizedClaims`] struct
//! that downstream modules (`jit`, `attribute_sync`, `role_mapping`) consume.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::ProvisioningError;

/// Unified claims extracted from either an OIDC ID token or a SAML assertion.
///
/// All fields are optional except `edipi_raw`, which is required for
/// identity correlation. Downstream consumers validate individual fields
/// as needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedClaims {
    /// Raw EDIPI string (10-digit) extracted from the token.
    pub edipi_raw: String,
    /// Display name (e.g., `"Doe, John Q."`).
    pub display_name: Option<String>,
    /// Organization / unit (e.g., `"42 CS, Maxwell AFB"`).
    pub organization: Option<String>,
    /// Email address.
    pub email: Option<String>,
    /// Site / installation identifier (from `IdP` claim `site` or `site_id`).
    ///
    /// Used to scope admin queries (AC-3). Absent for `IdP`s that do not
    /// project a site claim; such users are unattributed until a claim
    /// arrives on a subsequent login.
    pub site_id: Option<String>,
    /// `IdP` group memberships (raw group names from the `IdP`).
    pub groups: Vec<String>,
    /// Cost center code from `IdP` claims (if present).
    pub cost_center_code: Option<String>,
    /// Cost center name from `IdP` claims (if present).
    pub cost_center_name: Option<String>,
    /// The source of the claims (for audit trail).
    pub source: ClaimsSource,
    /// Any additional claims not mapped to specific fields.
    pub extra: HashMap<String, String>,
}

/// Identifies the identity protocol that produced the claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimsSource {
    /// Claims extracted from an OIDC ID token (`Entra ID`, `NIPR`).
    Oidc,
    /// Claims extracted from a SAML 2.0 assertion (DISA E-ICAM, `SIPR`).
    Saml,
}

/// Extract [`NormalizedClaims`] from a decoded OIDC ID token payload.
///
/// Expects a JSON object with standard OIDC claims plus `PrintForge`-specific
/// custom claims. Maps the `sub` claim to the EDIPI field.
///
/// # Errors
///
/// Returns `ProvisioningError::MissingClaims` if the `sub` claim (EDIPI) is absent.
/// Returns `ProvisioningError::ClaimsNormalization` if the JSON structure is unexpected.
pub fn normalize_oidc_claims(
    token_claims: &serde_json::Value,
) -> Result<NormalizedClaims, ProvisioningError> {
    let obj = token_claims
        .as_object()
        .ok_or_else(|| ProvisioningError::ClaimsNormalization {
            detail: "OIDC claims payload is not a JSON object".to_string(),
        })?;

    let edipi_raw = obj
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ProvisioningError::MissingClaims {
            field: "sub".to_string(),
        })?
        .to_string();

    let display_name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    let organization = obj
        .get("org")
        .or_else(|| obj.get("organization"))
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    let email = obj
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    let site_id = obj
        .get("site")
        .or_else(|| obj.get("site_id"))
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    let groups = extract_string_array(obj, "groups");

    let cost_center_code = obj
        .get("cost_center")
        .or_else(|| obj.get("cost_center_code"))
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    let cost_center_name = obj
        .get("cost_center_name")
        .and_then(serde_json::Value::as_str)
        .map(String::from);

    Ok(NormalizedClaims {
        edipi_raw,
        display_name,
        organization,
        email,
        site_id,
        groups,
        cost_center_code,
        cost_center_name,
        source: ClaimsSource::Oidc,
        extra: HashMap::new(),
    })
}

/// Extract [`NormalizedClaims`] from a decoded SAML assertion attribute map.
///
/// SAML attributes use URN-style names. This function maps well-known
/// SAML attribute names to `PrintForge` fields.
///
/// # Errors
///
/// Returns `ProvisioningError::MissingClaims` if the EDIPI attribute is absent.
/// Returns `ProvisioningError::ClaimsNormalization` if the attribute map is unexpected.
pub fn normalize_saml_claims<S: ::std::hash::BuildHasher>(
    attributes: &HashMap<String, Vec<String>, S>,
) -> Result<NormalizedClaims, ProvisioningError> {
    let edipi_raw = first_value(attributes, "urn:oid:1.3.6.1.4.1.5923.1.1.1.6")
        .or_else(|| first_value(attributes, "edipi"))
        .ok_or_else(|| ProvisioningError::MissingClaims {
            field: "edipi (urn:oid:1.3.6.1.4.1.5923.1.1.1.6)".to_string(),
        })?;

    let display_name = first_value(attributes, "urn:oid:2.16.840.1.113730.3.1.241")
        .or_else(|| first_value(attributes, "displayName"));

    let organization = first_value(attributes, "urn:oid:2.5.4.10")
        .or_else(|| first_value(attributes, "organization"));

    let email = first_value(attributes, "urn:oid:0.9.2342.19200300.100.1.3")
        .or_else(|| first_value(attributes, "email"));

    let site_id = first_value(attributes, "site").or_else(|| first_value(attributes, "site_id"));

    let groups = attributes
        .get("urn:oid:1.3.6.1.4.1.5923.1.1.1.7")
        .or_else(|| attributes.get("groups"))
        .cloned()
        .unwrap_or_default();

    let cost_center_code = first_value(attributes, "cost_center")
        .or_else(|| first_value(attributes, "cost_center_code"));

    let cost_center_name = first_value(attributes, "cost_center_name");

    Ok(NormalizedClaims {
        edipi_raw,
        display_name,
        organization,
        email,
        site_id,
        groups,
        cost_center_code,
        cost_center_name,
        source: ClaimsSource::Saml,
        extra: HashMap::new(),
    })
}

/// Extract the first value for a given key from a SAML attribute map.
fn first_value<S: ::std::hash::BuildHasher>(
    attributes: &HashMap<String, Vec<String>, S>,
    key: &str,
) -> Option<String> {
    attributes.get(key).and_then(|vals| vals.first()).cloned()
}

/// Extract a JSON array of strings from a JSON object field.
fn extract_string_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Vec<String> {
    obj.get(key)
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(serde_json::Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_oidc_extracts_all_fields() {
        let claims = serde_json::json!({
            "sub": "1234567890",
            "name": "DOE, JOHN Q.",
            "org": "42 CS, Maxwell AFB",
            "email": "john.doe@test.mil",
            "groups": ["PrintForge-Users", "PrintForge-SiteAdmin-Maxwell"],
            "cost_center": "CC001",
            "cost_center_name": "42nd Communications Squadron"
        });

        let normalized = normalize_oidc_claims(&claims).unwrap();
        assert_eq!(normalized.edipi_raw, "1234567890");
        assert_eq!(normalized.display_name.as_deref(), Some("DOE, JOHN Q."));
        assert_eq!(
            normalized.organization.as_deref(),
            Some("42 CS, Maxwell AFB")
        );
        assert_eq!(normalized.email.as_deref(), Some("john.doe@test.mil"));
        assert_eq!(normalized.groups.len(), 2);
        assert_eq!(normalized.cost_center_code.as_deref(), Some("CC001"));
        assert_eq!(normalized.source, ClaimsSource::Oidc);
    }

    #[test]
    fn nist_ac3_oidc_extracts_site_claim() {
        // NIST 800-53 Rev 5: AC-3 — Access Enforcement
        // Evidence: the OIDC `site` claim is normalized into NormalizedClaims
        // so JIT provisioning can attribute the user to an installation.
        let claims = serde_json::json!({
            "sub": "1234567890",
            "site": "maxwell"
        });
        let normalized = normalize_oidc_claims(&claims).unwrap();
        assert_eq!(normalized.site_id.as_deref(), Some("maxwell"));
    }

    #[test]
    fn oidc_accepts_site_id_claim_as_fallback() {
        // Some IdPs project the claim as `site_id` instead of `site`.
        let claims = serde_json::json!({
            "sub": "1234567890",
            "site_id": "ramstein"
        });
        let normalized = normalize_oidc_claims(&claims).unwrap();
        assert_eq!(normalized.site_id.as_deref(), Some("ramstein"));
    }

    #[test]
    fn nist_ac3_saml_extracts_site_attribute() {
        let mut attributes = HashMap::new();
        attributes.insert(
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6".to_string(),
            vec!["1234567890".to_string()],
        );
        attributes.insert("site".to_string(), vec!["maxwell".to_string()]);
        let normalized = normalize_saml_claims(&attributes).unwrap();
        assert_eq!(normalized.site_id.as_deref(), Some("maxwell"));
    }

    #[test]
    fn normalize_oidc_missing_sub_returns_error() {
        let claims = serde_json::json!({
            "name": "DOE, JOHN Q."
        });

        let result = normalize_oidc_claims(&claims);
        assert!(result.is_err());
    }

    #[test]
    fn normalize_oidc_minimal_claims() {
        let claims = serde_json::json!({
            "sub": "1234567890"
        });

        let normalized = normalize_oidc_claims(&claims).unwrap();
        assert_eq!(normalized.edipi_raw, "1234567890");
        assert!(normalized.display_name.is_none());
        assert!(normalized.groups.is_empty());
    }

    #[test]
    fn normalize_saml_extracts_all_fields() {
        let mut attributes = HashMap::new();
        attributes.insert(
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6".to_string(),
            vec!["1234567890".to_string()],
        );
        attributes.insert(
            "urn:oid:2.16.840.1.113730.3.1.241".to_string(),
            vec!["DOE, JOHN Q.".to_string()],
        );
        attributes.insert(
            "urn:oid:2.5.4.10".to_string(),
            vec!["42 CS, Maxwell AFB".to_string()],
        );
        attributes.insert(
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.7".to_string(),
            vec![
                "PrintForge-Users".to_string(),
                "PrintForge-SiteAdmin-Maxwell".to_string(),
            ],
        );
        attributes.insert("cost_center".to_string(), vec!["CC001".to_string()]);

        let normalized = normalize_saml_claims(&attributes).unwrap();
        assert_eq!(normalized.edipi_raw, "1234567890");
        assert_eq!(normalized.display_name.as_deref(), Some("DOE, JOHN Q."));
        assert_eq!(normalized.groups.len(), 2);
        assert_eq!(normalized.source, ClaimsSource::Saml);
    }

    #[test]
    fn normalize_saml_missing_edipi_returns_error() {
        let attributes = HashMap::new();
        let result = normalize_saml_claims(&attributes);
        assert!(result.is_err());
    }

    #[test]
    fn normalize_saml_fallback_field_names() {
        let mut attributes = HashMap::new();
        attributes.insert("edipi".to_string(), vec!["1234567890".to_string()]);
        attributes.insert("displayName".to_string(), vec!["DOE, JANE R.".to_string()]);
        attributes.insert("organization".to_string(), vec!["Test Org".to_string()]);

        let normalized = normalize_saml_claims(&attributes).unwrap();
        assert_eq!(normalized.edipi_raw, "1234567890");
        assert_eq!(normalized.display_name.as_deref(), Some("DOE, JANE R."));
        assert_eq!(normalized.organization.as_deref(), Some("Test Org"));
    }

    #[test]
    fn nist_ia2_oidc_claims_require_edipi() {
        // NIST 800-53 Rev 5: IA-2 — Identification and Authentication
        // Evidence: OIDC claims normalization requires a subject (EDIPI).
        let claims = serde_json::json!({"name": "no edipi"});
        assert!(normalize_oidc_claims(&claims).is_err());
    }

    #[test]
    fn nist_ia2_saml_claims_require_edipi() {
        // NIST 800-53 Rev 5: IA-2 — Identification and Authentication
        // Evidence: SAML claims normalization requires an EDIPI attribute.
        let attributes = HashMap::new();
        assert!(normalize_saml_claims(&attributes).is_err());
    }
}
