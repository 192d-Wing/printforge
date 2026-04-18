// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Follow-Me hold enforcement for ingested print jobs.
//!
//! Every job submitted through the `IPPS` driver service MUST have its
//! `job-hold-until` attribute set to `indefinite`, regardless of the value
//! sent by the client. This is the core mechanism of `PrintForge` Follow-Me
//! printing: jobs are held until explicitly released at a physical printer.
//!
//! **NIST 800-53 Rev 5:** AU-2 — Event Logging (hold enforcement is auditable)

use crate::ipp_parser::{IppAttribute, IppAttributeGroup, ValueTag};

/// The required hold value per the Follow-Me printing model.
pub const HOLD_VALUE: &str = "indefinite";

/// The `IPP` attribute name for job hold control.
pub const HOLD_ATTRIBUTE_NAME: &str = "job-hold-until";

/// Enforces `job-hold-until=indefinite` on an `IPP` attribute group.
///
/// If the attribute is already present, its value is overwritten.
/// If it is absent, it is appended to the group.
///
/// Returns `true` if the original value was overridden (client sent
/// a different value), `false` if the attribute was absent or already correct.
pub fn enforce_hold(job_attrs: &mut IppAttributeGroup) -> bool {
    let hold_bytes = bytes::Bytes::from_static(HOLD_VALUE.as_bytes());

    // Check if the attribute already exists
    if let Some(attr) = job_attrs
        .attributes
        .iter_mut()
        .find(|a| a.name == HOLD_ATTRIBUTE_NAME)
    {
        let was_different = attr.value != hold_bytes;
        if was_different {
            tracing::warn!(
                original_value = %String::from_utf8_lossy(&attr.value),
                enforced_value = HOLD_VALUE,
                "overriding client job-hold-until value — Follow-Me enforcement"
            );
            attr.value = hold_bytes;
            attr.value_tag = ValueTag::Keyword;
        }
        return was_different;
    }

    // Attribute not present — add it
    job_attrs.attributes.push(IppAttribute {
        name: HOLD_ATTRIBUTE_NAME.to_string(),
        value_tag: ValueTag::Keyword,
        value: hold_bytes,
    });

    false
}

/// Check whether a job-attributes group already has the correct hold value.
#[must_use]
pub fn is_hold_enforced(job_attrs: &IppAttributeGroup) -> bool {
    job_attrs
        .find_attribute(HOLD_ATTRIBUTE_NAME)
        .is_some_and(|attr| attr.value.as_ref() == HOLD_VALUE.as_bytes())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::ipp_parser::AttributeGroupTag;

    fn make_job_group(attrs: Vec<IppAttribute>) -> IppAttributeGroup {
        IppAttributeGroup {
            tag: AttributeGroupTag::JobAttributes,
            attributes: attrs,
        }
    }

    #[test]
    fn enforce_hold_adds_attribute_when_absent() {
        let mut group = make_job_group(vec![]);
        let overridden = enforce_hold(&mut group);
        assert!(!overridden);
        assert!(is_hold_enforced(&group));
    }

    #[test]
    fn enforce_hold_overrides_no_hold() {
        let mut group = make_job_group(vec![IppAttribute {
            name: HOLD_ATTRIBUTE_NAME.to_string(),
            value_tag: ValueTag::Keyword,
            value: Bytes::from_static(b"no-hold"),
        }]);
        let overridden = enforce_hold(&mut group);
        assert!(overridden);
        assert!(is_hold_enforced(&group));
    }

    #[test]
    fn enforce_hold_preserves_indefinite() {
        let mut group = make_job_group(vec![IppAttribute {
            name: HOLD_ATTRIBUTE_NAME.to_string(),
            value_tag: ValueTag::Keyword,
            value: Bytes::from_static(b"indefinite"),
        }]);
        let overridden = enforce_hold(&mut group);
        assert!(!overridden);
        assert!(is_hold_enforced(&group));
    }

    #[test]
    fn nist_au2_hold_enforcement_overrides_any_client_value() {
        // NIST 800-53 Rev 5: AU-2 — Event Logging
        // Evidence: any client-supplied hold value is overridden to "indefinite"
        for client_value in &[
            "no-hold",
            "day-time",
            "evening",
            "night",
            "weekend",
            "second-shift",
            "third-shift",
        ] {
            let mut group = make_job_group(vec![IppAttribute {
                name: HOLD_ATTRIBUTE_NAME.to_string(),
                value_tag: ValueTag::Keyword,
                value: Bytes::from(client_value.to_string()),
            }]);
            let overridden = enforce_hold(&mut group);
            assert!(overridden, "should override value: {client_value}");
            assert!(
                is_hold_enforced(&group),
                "hold not enforced after overriding: {client_value}"
            );
        }
    }

    #[test]
    fn is_hold_enforced_returns_false_when_absent() {
        let group = make_job_group(vec![]);
        assert!(!is_hold_enforced(&group));
    }
}
