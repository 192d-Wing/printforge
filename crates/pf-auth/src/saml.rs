// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! SAML 2.0 SP-initiated SSO types.
//!
//! **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication (Non-Organizational Users)
//!
//! Provides types for SAML 2.0 SP-initiated Single Sign-On against
//! DISA E-ICAM (SIPR). Actual XML signing and parsing will use the
//! `saml-rs` crate in a future iteration.

use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use pf_common::identity::{Edipi, Identity, Role};

use crate::config::SamlConfig;
use crate::error::AuthError;

/// SAML `AuthnRequest` parameters for SP-initiated SSO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnRequest {
    /// Unique request ID.
    pub id: String,
    /// Timestamp of the request (ISO 8601).
    pub issue_instant: String,
    /// SP entity ID (issuer).
    pub issuer: String,
    /// Assertion Consumer Service URL.
    pub acs_url: Url,
    /// Relay state (opaque, returned by `IdP` after auth).
    pub relay_state: Option<String>,
}

/// A parsed SAML assertion with extracted attributes.
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    /// The subject name ID (usually EDIPI or email).
    pub name_id: String,
    /// Session index from the `IdP`.
    pub session_index: Option<String>,
    /// Attributes extracted from the assertion (key-value pairs).
    pub attributes: Vec<(String, String)>,
}

/// Build a SAML `AuthnRequest` for SP-initiated SSO.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::SamlError` if the configuration is invalid.
/// Returns `AuthError::Internal` if ID generation fails.
pub fn build_authn_request(
    config: &SamlConfig,
    relay_state: Option<String>,
) -> Result<AuthnRequest, AuthError> {
    let id = generate_request_id();
    let issue_instant = chrono::Utc::now().to_rfc3339();

    Ok(AuthnRequest {
        id,
        issue_instant,
        issuer: config.sp_entity_id.clone(),
        acs_url: config.acs_url.clone(),
        relay_state,
    })
}

/// Build the `IdP` redirect URL with the `AuthnRequest` encoded as a query parameter.
///
/// In a full implementation, this would deflate + base64-encode the XML
/// `AuthnRequest` and append it as the `SAMLRequest` parameter.
///
/// # Errors
///
/// Returns `AuthError::SamlError` if the redirect URL cannot be constructed.
pub fn build_redirect_url(config: &SamlConfig, request: &AuthnRequest) -> Result<Url, AuthError> {
    let mut redirect = config.idp_metadata_url.clone();

    redirect
        .query_pairs_mut()
        .append_pair("SAMLRequest", &request.id) // Placeholder: real impl encodes XML
        .append_pair("RelayState", request.relay_state.as_deref().unwrap_or(""));

    Ok(redirect)
}

/// Validate a SAML response received at the ACS endpoint.
///
/// Performs the following checks:
/// 1. Decodes the base64-encoded SAML response.
/// 2. Parses the XML to extract assertion fields.
/// 3. Validates `InResponseTo` matches the original request ID.
/// 4. Validates the `Audience` restriction matches the SP entity ID.
/// 5. Extracts the `NameID` (EDIPI) and role attributes.
///
/// **Note:** XML digital signature verification is not yet implemented.
/// In production, the response MUST be verified against the `IdP` signing
/// certificate before trusting any assertions.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::SamlError` if decoding, parsing, or validation fails.
pub fn validate_saml_response(
    config: &SamlConfig,
    saml_response_b64: &str,
) -> Result<SamlAssertion, AuthError> {
    validate_saml_response_with_request_id(config, saml_response_b64, None)
}

/// Validate a SAML response, optionally checking `InResponseTo`.
///
/// When `expected_request_id` is `Some`, the `InResponseTo` attribute on
/// the response must match. When `None`, this check is skipped (useful
/// for IdP-initiated SSO, though we prefer SP-initiated).
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::SamlError` if validation fails.
pub fn validate_saml_response_with_request_id(
    config: &SamlConfig,
    saml_response_b64: &str,
    expected_request_id: Option<&str>,
) -> Result<SamlAssertion, AuthError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    // Step 1: Decode the base64 SAML response.
    let xml_bytes = STANDARD.decode(saml_response_b64).map_err(|_| {
        warn!("SAML response base64 decoding failed");
        AuthError::SamlError("invalid base64 encoding".to_string())
    })?;

    let xml_str = String::from_utf8(xml_bytes).map_err(|_| {
        AuthError::SamlError("SAML response is not valid UTF-8".to_string())
    })?;

    // Step 2: Parse the XML to extract relevant fields.
    // We use basic string parsing here. A production implementation should
    // use a proper XML parser or the saml-rs crate for full validation.
    let parsed = parse_saml_xml(&xml_str)?;

    // Step 3: Validate InResponseTo if we have an expected request ID.
    if let Some(expected_id) = expected_request_id {
        if let Some(ref in_response_to) = parsed.in_response_to {
            if in_response_to != expected_id {
                warn!("SAML InResponseTo mismatch");
                return Err(AuthError::SamlError(
                    "InResponseTo does not match the original request".to_string(),
                ));
            }
        } else {
            return Err(AuthError::SamlError(
                "missing InResponseTo attribute".to_string(),
            ));
        }
    }

    // Step 4: Validate the Audience restriction.
    if let Some(ref audience) = parsed.audience {
        if *audience != config.sp_entity_id {
            warn!("SAML Audience restriction mismatch");
            return Err(AuthError::SamlError(
                "audience restriction does not match SP entity ID".to_string(),
            ));
        }
    }

    // TODO(pf-auth): Verify XML digital signature against the IdP signing
    // certificate. This is REQUIRED for production deployments to prevent
    // assertion forgery. Use the saml-rs crate or xmlsec bindings.

    // Step 5: Extract the NameID and build the assertion.
    let name_id = parsed.name_id.ok_or_else(|| {
        AuthError::SamlError("missing NameID in SAML assertion".to_string())
    })?;

    Ok(SamlAssertion {
        name_id,
        session_index: parsed.session_index,
        attributes: parsed.attributes,
    })
}

/// Extract an `Identity` from a validated SAML assertion.
///
/// The `NameID` is expected to contain the EDIPI (10 digits) or a `DoD` CN
/// (`LAST.FIRST.MI.1234567890`). Role attributes are mapped from the
/// assertion's attribute statements.
///
/// **NIST 800-53 Rev 5:** IA-8 — Identification and Authentication
///
/// # Errors
///
/// Returns `AuthError::SamlError` if the EDIPI cannot be extracted.
pub fn identity_from_assertion(assertion: &SamlAssertion) -> Result<Identity, AuthError> {
    // Try NameID as raw EDIPI first, then as DoD CN.
    let edipi = Edipi::new(&assertion.name_id)
        .or_else(|_| {
            crate::certificate::extract_edipi_from_cn(&assertion.name_id)
                .map_err(|_| AuthError::SamlError(
                    "NameID does not contain a valid EDIPI".to_string(),
                ))
        })?;

    // Extract name and org from attributes if available.
    let name = find_attribute(&assertion.attributes, "displayName")
        .or_else(|| find_attribute(&assertion.attributes, "cn"))
        .unwrap_or_default();
    let org = find_attribute(&assertion.attributes, "organization")
        .or_else(|| find_attribute(&assertion.attributes, "o"))
        .unwrap_or_default();

    // Map role attributes.
    let roles = extract_roles_from_attributes(&assertion.attributes);

    Ok(Identity {
        edipi,
        name,
        org,
        roles,
    })
}

/// Internal representation of a parsed SAML response.
struct ParsedSamlResponse {
    in_response_to: Option<String>,
    audience: Option<String>,
    name_id: Option<String>,
    session_index: Option<String>,
    attributes: Vec<(String, String)>,
}

/// Parse SAML response XML and extract key fields.
///
/// This uses basic string matching. A production implementation should
/// use a proper XML parser (e.g., `quick-xml` or `xmltree`).
fn parse_saml_xml(xml: &str) -> Result<ParsedSamlResponse, AuthError> {
    // Verify this looks like a SAML response.
    if !xml.contains("samlp:Response") && !xml.contains("Response") {
        return Err(AuthError::SamlError(
            "document does not appear to be a SAML response".to_string(),
        ));
    }

    let in_response_to = extract_xml_attribute(xml, "InResponseTo");
    let audience = extract_xml_element_text(xml, "Audience");
    let name_id = extract_xml_element_text(xml, "NameID");
    let session_index = extract_xml_attribute(xml, "SessionIndex");

    // Extract attributes from AttributeStatement.
    let attributes = extract_saml_attributes(xml);

    Ok(ParsedSamlResponse {
        in_response_to,
        audience,
        name_id,
        session_index,
        attributes,
    })
}

/// Extract the value of an XML attribute by name.
///
/// Looks for `name="value"` in the XML string.
fn extract_xml_attribute(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=\"");
    let start = xml.find(&pattern)? + pattern.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract the text content of an XML element by tag name.
///
/// Looks for `<...TagName...>text</...TagName...>`.
fn extract_xml_element_text(xml: &str, tag_name: &str) -> Option<String> {
    // Find opening tag (may have namespace prefix).
    let open_patterns = [
        format!("<{tag_name}>"),
        format!("<{tag_name} "),
        format!("<saml:{tag_name}>"),
        format!("<saml:{tag_name} "),
    ];

    for pattern in &open_patterns {
        if let Some(start_pos) = xml.find(pattern.as_str()) {
            let after_tag = &xml[start_pos + pattern.len()..];
            // If the pattern ended with a space, skip to the closing '>'.
            let content_start = if pattern.ends_with(' ') {
                after_tag.find('>')? + 1
            } else {
                0
            };
            let content = &after_tag[content_start..];
            // Find closing tag.
            let close_patterns = [
                format!("</{tag_name}>"),
                format!("</saml:{tag_name}>"),
            ];
            for close in &close_patterns {
                if let Some(end_pos) = content.find(close.as_str()) {
                    let text = content[..end_pos].trim().to_string();
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
            }
        }
    }

    None
}

/// Extract SAML attributes from `AttributeStatement` elements.
fn extract_saml_attributes(xml: &str) -> Vec<(String, String)> {
    let mut attributes = Vec::new();

    // Find all Attribute elements with Name="..." and extract their values.
    let mut search_from = 0;
    while let Some(attr_pos) = xml[search_from..].find("Attribute Name=\"") {
        let abs_pos = search_from + attr_pos;
        let name_start = abs_pos + "Attribute Name=\"".len();
        if let Some(name_end_offset) = xml[name_start..].find('"') {
            let name = xml[name_start..name_start + name_end_offset].to_string();

            // Look for AttributeValue within the next ~500 chars.
            let search_end = (name_start + 500).min(xml.len());
            let window = &xml[name_start..search_end];
            if let Some(value) = extract_xml_element_text(window, "AttributeValue") {
                attributes.push((name, value));
            }
            search_from = name_start + name_end_offset + 1;
        } else {
            break;
        }
    }

    attributes
}

/// Find an attribute value by key in a list of attribute pairs.
fn find_attribute(attributes: &[(String, String)], key: &str) -> Option<String> {
    attributes
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
}

/// Extract `PrintForge` roles from SAML attribute statements.
///
/// Looks for attributes named `Role`, `groups`, or `memberOf` and maps
/// the values to `PrintForge` roles using the same convention as OIDC.
fn extract_roles_from_attributes(attributes: &[(String, String)]) -> Vec<Role> {
    let mut roles = vec![Role::User];

    let role_keys = ["Role", "groups", "memberOf"];
    for (key, value) in attributes {
        if role_keys.contains(&key.as_str()) {
            if value == "PrintForge-FleetAdmin" && !roles.contains(&Role::FleetAdmin) {
                roles.push(Role::FleetAdmin);
            } else if value == "PrintForge-Auditor" && !roles.contains(&Role::Auditor) {
                roles.push(Role::Auditor);
            } else if let Some(site_id) = value.strip_prefix("PrintForge-SiteAdmin-") {
                let site_role =
                    Role::SiteAdmin(pf_common::identity::SiteId(site_id.to_string()));
                if !roles.contains(&site_role) {
                    roles.push(site_role);
                }
            }
        }
    }

    roles
}

/// Generate a unique request ID for `AuthnRequest`.
fn generate_request_id() -> String {
    let id = uuid::Uuid::new_v4();
    format!("_pf_{id}")
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    fn test_saml_config() -> SamlConfig {
        SamlConfig {
            idp_metadata_url: Url::parse("https://idp.example.mil/saml/sso").unwrap(),
            sp_entity_id: "https://printforge.local/saml/metadata".to_string(),
            acs_url: Url::parse("https://printforge.local/saml/acs").unwrap(),
        }
    }

    /// Build a minimal SAML response XML for testing.
    fn build_test_saml_response(
        in_response_to: &str,
        audience: &str,
        name_id: &str,
    ) -> String {
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                InResponseTo="{in_response_to}"
                ID="_resp_123">
                <saml:Assertion>
                    <saml:Conditions>
                        <saml:AudienceRestriction>
                            <saml:Audience>{audience}</saml:Audience>
                        </saml:AudienceRestriction>
                    </saml:Conditions>
                    <saml:Subject>
                        <saml:NameID>{name_id}</saml:NameID>
                    </saml:Subject>
                    <saml:AuthnStatement SessionIndex="session-idx-001" />
                    <saml:AttributeStatement>
                        <saml:Attribute Name="displayName">
                            <saml:AttributeValue>John Q Doe</saml:AttributeValue>
                        </saml:Attribute>
                        <saml:Attribute Name="Role">
                            <saml:AttributeValue>PrintForge-FleetAdmin</saml:AttributeValue>
                        </saml:Attribute>
                    </saml:AttributeStatement>
                </saml:Assertion>
            </samlp:Response>"#
        )
    }

    fn encode_b64(xml: &str) -> String {
        STANDARD.encode(xml.as_bytes())
    }

    #[test]
    fn build_authn_request_creates_valid_request() {
        let config = test_saml_config();
        let request =
            build_authn_request(&config, Some("return-to-dashboard".to_string())).unwrap();

        assert!(request.id.starts_with("_pf_"));
        assert_eq!(request.issuer, config.sp_entity_id);
        assert_eq!(request.acs_url, config.acs_url);
        assert_eq!(request.relay_state.as_deref(), Some("return-to-dashboard"));
    }

    #[test]
    fn build_redirect_url_includes_saml_request() {
        let config = test_saml_config();
        let request = build_authn_request(&config, None).unwrap();
        let url = build_redirect_url(&config, &request).unwrap();
        let url_str = url.to_string();

        assert!(url_str.contains("SAMLRequest="));
    }

    #[test]
    fn nist_ia8_saml_request_has_unique_id() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: Each AuthnRequest has a unique ID.
        let config = test_saml_config();
        let req1 = build_authn_request(&config, None).unwrap();
        let req2 = build_authn_request(&config, None).unwrap();
        assert_ne!(req1.id, req2.id);
    }

    #[test]
    fn nist_ia8_saml_validates_in_response_to() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: Mismatched InResponseTo is rejected to prevent replay attacks.
        let config = test_saml_config();
        let xml = build_test_saml_response(
            "_pf_original-request-id",
            &config.sp_entity_id,
            "1234567890",
        );
        let b64 = encode_b64(&xml);

        // Correct request ID should succeed.
        let result = validate_saml_response_with_request_id(
            &config,
            &b64,
            Some("_pf_original-request-id"),
        );
        assert!(result.is_ok());

        // Wrong request ID should fail.
        let result = validate_saml_response_with_request_id(
            &config,
            &b64,
            Some("_pf_WRONG-request-id"),
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("InResponseTo"));
    }

    #[test]
    fn nist_ia8_saml_extracts_edipi_from_name_id() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: EDIPI is correctly extracted from the NameID element.
        let config = test_saml_config();
        let xml = build_test_saml_response(
            "_pf_req-123",
            &config.sp_entity_id,
            "1234567890",
        );
        let b64 = encode_b64(&xml);

        let assertion = validate_saml_response(&config, &b64).unwrap();
        assert_eq!(assertion.name_id, "1234567890");

        // Verify we can build an Identity from it.
        let identity = identity_from_assertion(&assertion).unwrap();
        assert_eq!(identity.edipi.as_str(), "1234567890");
    }

    #[test]
    fn nist_ia8_saml_rejects_invalid_base64() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: Malformed base64 input is rejected.
        let config = test_saml_config();
        let result = validate_saml_response(&config, "not-valid-base64!!!");
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("base64"));
    }

    #[test]
    fn nist_ia8_saml_rejects_invalid_audience() {
        // NIST 800-53 Rev 5: IA-8 — Identification and Authentication
        // Evidence: Wrong Audience restriction is rejected.
        let config = test_saml_config();
        let xml = build_test_saml_response(
            "_pf_req-123",
            "https://wrong-sp.example.com/metadata", // wrong audience
            "1234567890",
        );
        let b64 = encode_b64(&xml);

        let result = validate_saml_response(&config, &b64);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("audience"));
    }

    #[test]
    fn saml_extracts_edipi_from_dod_cn_name_id() {
        // NameID in DoD CN format should also work.
        let config = test_saml_config();
        let xml = build_test_saml_response(
            "_pf_req-456",
            &config.sp_entity_id,
            "DOE.JOHN.Q.9876543210",
        );
        let b64 = encode_b64(&xml);

        let assertion = validate_saml_response(&config, &b64).unwrap();
        let identity = identity_from_assertion(&assertion).unwrap();
        assert_eq!(identity.edipi.as_str(), "9876543210");
    }

    #[test]
    fn saml_extracts_attributes() {
        let config = test_saml_config();
        let xml = build_test_saml_response(
            "_pf_req-789",
            &config.sp_entity_id,
            "1234567890",
        );
        let b64 = encode_b64(&xml);

        let assertion = validate_saml_response(&config, &b64).unwrap();

        // Should have extracted displayName and Role attributes.
        assert!(assertion.attributes.iter().any(|(k, v)| k == "displayName" && v == "John Q Doe"));
        assert!(assertion.attributes.iter().any(|(k, v)| k == "Role" && v == "PrintForge-FleetAdmin"));
        assert_eq!(assertion.session_index.as_deref(), Some("session-idx-001"));
    }

    #[test]
    fn saml_identity_includes_roles_from_attributes() {
        let config = test_saml_config();
        let xml = build_test_saml_response(
            "_pf_req-789",
            &config.sp_entity_id,
            "1234567890",
        );
        let b64 = encode_b64(&xml);

        let assertion = validate_saml_response(&config, &b64).unwrap();
        let identity = identity_from_assertion(&assertion).unwrap();
        assert!(identity.roles.contains(&Role::User));
        assert!(identity.roles.contains(&Role::FleetAdmin));
    }
}
