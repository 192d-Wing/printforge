// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Property-based tests for `pf-common` types.
//!
//! Uses `proptest` to verify invariants across a wide range of inputs,
//! complementing the hand-written unit tests in each module.

use std::collections::HashSet;

use proptest::prelude::*;

use pf_common::fleet::PrinterId;
use pf_common::identity::Edipi;
use pf_common::job::{CostCenter, JobId};
use pf_common::validated::validate_non_empty;

proptest! {
    /// Any 10-digit ASCII string accepted by `Edipi::new()` round-trips
    /// through `as_str()` without modification.
    #[test]
    fn prop_edipi_roundtrip(s in "[0-9]{10}") {
        let edipi = Edipi::new(&s).unwrap();
        prop_assert_eq!(edipi.as_str(), s.as_str());
    }

    /// Strings that are NOT exactly 10 ASCII digits are always rejected
    /// by `Edipi::new()`.
    #[test]
    fn prop_edipi_rejects_non_10_digit(s in "[^0-9]{1,20}|[0-9]{0,9}|[0-9]{11,20}") {
        prop_assert!(Edipi::new(&s).is_err());
    }

    /// The `Display` implementation of `Edipi` never exposes the raw
    /// digits — it always outputs the redacted placeholder.
    #[test]
    fn prop_edipi_display_never_leaks_value(s in "[0-9]{10}") {
        let edipi = Edipi::new(&s).unwrap();
        let display = format!("{edipi}");
        prop_assert!(!display.contains(&s), "Display leaked raw EDIPI: {}", display);
    }

    /// 100 generated `JobId`s are all distinct (UUIDv7 monotonic uniqueness).
    #[test]
    fn prop_job_id_generate_is_unique(_ in 0u8..1) {
        let ids: HashSet<_> = (0..100)
            .map(|_| *JobId::generate().as_uuid())
            .collect();
        prop_assert_eq!(ids.len(), 100);
    }

    /// `CostCenter::new()` rejects empty or whitespace-only `code` values.
    #[test]
    fn prop_cost_center_rejects_empty_fields(
        spaces in " {0,10}",
        name in "\\PC{0,20}",
    ) {
        // A code that is only whitespace (including empty) must be rejected.
        prop_assert!(CostCenter::new(&spaces, &name).is_err());
    }

    /// Strings that do not start with `PRN-` followed by at least one
    /// character are always rejected by `PrinterId::new()`.
    #[test]
    fn prop_printer_id_rejects_invalid_format(s in "[^P]\\PC{0,20}|P[^R]\\PC{0,20}|PR[^N]\\PC{0,20}|PRN[^-]\\PC{0,20}|PRN-|.{0,3}") {
        prop_assert!(PrinterId::new(&s).is_err());
    }

    /// `validate_non_empty` rejects strings composed entirely of whitespace.
    #[test]
    fn prop_validate_non_empty_rejects_blank(s in "[ \\t\\n\\r]{1,50}") {
        prop_assert!(validate_non_empty("test_field", &s, 1000).is_err());
    }
}
