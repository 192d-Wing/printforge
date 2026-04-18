// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! `SCIM` filter parser (`RFC 7644` Section 3.4.2.2).
//!
//! Parses simple `SCIM` filter expressions such as:
//! - `userName eq "1234567890"`
//! - `active eq true`
//! - `displayName co "Doe"`
//! - `userName sw "123"`
//!
//! Only simple attribute-operator-value expressions are supported.
//! Complex boolean expressions (`and`, `or`, `not`) are not implemented.

use crate::user::ProvisionedUser;

/// Supported `SCIM` filter comparison operators (`RFC 7644` Section 3.4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    /// Equal (`eq`).
    Eq,
    /// Contains (`co`).
    Contains,
    /// Starts with (`sw`).
    StartsWith,
}

/// A parsed `SCIM` filter expression.
///
/// Represents a single `attribute op value` filter clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimFilter {
    /// The attribute path (e.g., `"userName"`, `"active"`, `"displayName"`).
    pub attribute: String,
    /// The comparison operator.
    pub op: FilterOp,
    /// The comparison value (as a string; booleans are `"true"`/`"false"`).
    pub value: String,
}

/// Errors that can occur while parsing a `SCIM` filter expression.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterParseError {
    /// The filter string was empty.
    #[error("empty filter expression")]
    Empty,

    /// The filter expression could not be parsed (wrong number of tokens).
    #[error("invalid filter syntax")]
    InvalidSyntax,

    /// The operator is not recognized.
    #[error("unsupported filter operator: {0}")]
    UnsupportedOperator(String),
}

/// Parse a `SCIM` filter string into a [`ScimFilter`].
///
/// # Supported formats
///
/// - `attribute eq "value"` — exact match (string)
/// - `attribute eq true`    — exact match (boolean)
/// - `attribute co "value"` — substring contains
/// - `attribute sw "value"` — prefix match
///
/// # Errors
///
/// Returns [`FilterParseError`] if the filter is empty, has invalid syntax,
/// or uses an unsupported operator.
pub fn parse_filter(filter: &str) -> Result<ScimFilter, FilterParseError> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Err(FilterParseError::Empty);
    }

    // Tokenize: attribute, operator, value (which may be quoted).
    let mut parts = filter.splitn(3, ' ');

    let attribute = parts
        .next()
        .ok_or(FilterParseError::InvalidSyntax)?
        .to_string();

    let op_str = parts.next().ok_or(FilterParseError::InvalidSyntax)?;

    let op = match op_str.to_lowercase().as_str() {
        "eq" => FilterOp::Eq,
        "co" => FilterOp::Contains,
        "sw" => FilterOp::StartsWith,
        other => return Err(FilterParseError::UnsupportedOperator(other.to_string())),
    };

    let raw_value = parts.next().ok_or(FilterParseError::InvalidSyntax)?.trim();

    // Strip surrounding quotes if present.
    let value = if raw_value.starts_with('"') && raw_value.ends_with('"') && raw_value.len() >= 2 {
        raw_value[1..raw_value.len() - 1].to_string()
    } else {
        raw_value.to_string()
    };

    Ok(ScimFilter {
        attribute,
        op,
        value,
    })
}

/// Test whether a [`ProvisionedUser`] matches the given [`ScimFilter`].
///
/// Supports filtering on `userName`, `active`, and `displayName` attributes.
/// Unknown attributes never match.
#[must_use]
pub fn matches_filter(user: &ProvisionedUser, filter: &ScimFilter) -> bool {
    let field_value = match filter.attribute.as_str() {
        "userName" => Some(user.edipi.as_str().to_string()),
        "active" => Some(user.is_active().to_string()),
        "displayName" => Some(user.display_name.clone()),
        _ => None,
    };

    let Some(field_value) = field_value else {
        return false;
    };

    match filter.op {
        FilterOp::Eq => field_value == filter.value,
        FilterOp::Contains => field_value.contains(&filter.value),
        FilterOp::StartsWith => field_value.starts_with(&filter.value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::{ProvisioningSource, UserPreferences, UserStatus};
    use chrono::Utc;
    use pf_common::identity::{Edipi, Role};
    use pf_common::job::CostCenter;
    use uuid::Uuid;

    fn test_user() -> ProvisionedUser {
        let now = Utc::now();
        ProvisionedUser {
            id: Uuid::new_v4(),
            edipi: Edipi::new("1234567890").unwrap(),
            display_name: "DOE, JOHN Q.".to_string(),
            organization: "Test Unit, Test Base AFB".to_string(),
            roles: vec![Role::User],
            cost_centers: vec![CostCenter::new("CC001", "Test").unwrap()],
            preferences: UserPreferences::default(),
            status: UserStatus::Active,
            provisioning_source: ProvisioningSource::Jit,
            created_at: now,
            updated_at: now,
            last_login_at: None,
        }
    }

    #[test]
    fn parse_eq_string_filter() {
        let f = parse_filter(r#"userName eq "1234567890""#).unwrap();
        assert_eq!(f.attribute, "userName");
        assert_eq!(f.op, FilterOp::Eq);
        assert_eq!(f.value, "1234567890");
    }

    #[test]
    fn parse_eq_boolean_filter() {
        let f = parse_filter("active eq true").unwrap();
        assert_eq!(f.attribute, "active");
        assert_eq!(f.op, FilterOp::Eq);
        assert_eq!(f.value, "true");
    }

    #[test]
    fn parse_co_filter() {
        let f = parse_filter(r#"displayName co "Doe""#).unwrap();
        assert_eq!(f.attribute, "displayName");
        assert_eq!(f.op, FilterOp::Contains);
        assert_eq!(f.value, "Doe");
    }

    #[test]
    fn parse_sw_filter() {
        let f = parse_filter(r#"userName sw "123""#).unwrap();
        assert_eq!(f.attribute, "userName");
        assert_eq!(f.op, FilterOp::StartsWith);
        assert_eq!(f.value, "123");
    }

    #[test]
    fn parse_empty_filter_fails() {
        let result = parse_filter("");
        assert_eq!(result, Err(FilterParseError::Empty));
    }

    #[test]
    fn parse_missing_value_fails() {
        let result = parse_filter("userName eq");
        assert_eq!(result, Err(FilterParseError::InvalidSyntax));
    }

    #[test]
    fn parse_unsupported_operator_fails() {
        let result = parse_filter(r#"userName gt "123""#);
        assert!(matches!(
            result,
            Err(FilterParseError::UnsupportedOperator(_))
        ));
    }

    #[test]
    fn parse_case_insensitive_operator() {
        let f = parse_filter(r#"userName EQ "1234567890""#).unwrap();
        assert_eq!(f.op, FilterOp::Eq);
    }

    #[test]
    fn matches_filter_eq_username() {
        let user = test_user();
        let f = parse_filter(r#"userName eq "1234567890""#).unwrap();
        assert!(matches_filter(&user, &f));
    }

    #[test]
    fn matches_filter_eq_username_no_match() {
        let user = test_user();
        let f = parse_filter(r#"userName eq "9999999999""#).unwrap();
        assert!(!matches_filter(&user, &f));
    }

    #[test]
    fn matches_filter_active_true() {
        let user = test_user();
        let f = parse_filter("active eq true").unwrap();
        assert!(matches_filter(&user, &f));
    }

    #[test]
    fn matches_filter_active_false() {
        let user = test_user();
        let f = parse_filter("active eq false").unwrap();
        assert!(!matches_filter(&user, &f));
    }

    #[test]
    fn matches_filter_display_name_contains() {
        let user = test_user();
        let f = parse_filter(r#"displayName co "DOE""#).unwrap();
        assert!(matches_filter(&user, &f));
    }

    #[test]
    fn matches_filter_display_name_starts_with() {
        let user = test_user();
        let f = parse_filter(r#"displayName sw "DOE""#).unwrap();
        assert!(matches_filter(&user, &f));
    }

    #[test]
    fn matches_filter_unknown_attribute_returns_false() {
        let user = test_user();
        let f = ScimFilter {
            attribute: "unknownAttr".to_string(),
            op: FilterOp::Eq,
            value: "something".to_string(),
        };
        assert!(!matches_filter(&user, &f));
    }

    #[test]
    fn parse_filter_trims_whitespace() {
        let f = parse_filter(r#"  userName eq "1234567890"  "#).unwrap();
        assert_eq!(f.attribute, "userName");
        assert_eq!(f.value, "1234567890");
    }
}
