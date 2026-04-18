// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! UTC timestamp utilities.
//!
//! All timestamps in `PrintForge` are UTC. This module provides
//! convenience wrappers to enforce that invariant.

use chrono::{DateTime, Utc};

/// Return the current UTC timestamp.
#[must_use]
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Format a UTC timestamp as an ISO 8601 / RFC 3339 string.
#[must_use]
pub fn to_rfc3339(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

/// Parse an RFC 3339 string into a UTC `DateTime`.
///
/// # Errors
///
/// Returns an error if the string is not valid RFC 3339.
pub fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    s.parse::<DateTime<Utc>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_utc() {
        let ts = now();
        assert_eq!(ts.timezone(), Utc);
    }

    #[test]
    fn roundtrip_rfc3339() {
        let ts = now();
        let s = to_rfc3339(&ts);
        let parsed = parse_rfc3339(&s).unwrap();
        assert_eq!(ts, parsed);
    }
}
