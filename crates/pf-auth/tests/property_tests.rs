// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Property-based tests for `pf-auth` certificate and EDIPI extraction.
//!
//! **NIST 800-53 Rev 5:** IA-2(12) — Accept PIV Credentials,
//! IA-5(2) — PKI-Based Authentication

use proptest::prelude::*;

use pf_auth::certificate::{extract_edipi_from_cn, ParsedCertificate};

proptest! {
    /// Arbitrary string input to `extract_edipi_from_cn()` must never panic.
    /// It must always return `Ok` or `Err`.
    #[test]
    fn prop_extract_edipi_never_panics(cn in "\\PC{0,200}") {
        let _ = extract_edipi_from_cn(&cn);
    }

    /// Common names matching the DoD format `LAST.FIRST.MI.1234567890`
    /// always extract a valid EDIPI equal to the trailing 10 digits.
    #[test]
    fn prop_edipi_from_valid_dod_cn(
        last in "[A-Z]{2,20}",
        first in "[A-Z]{2,20}",
        mi in "[A-Z]",
        digits in "[0-9]{10}",
    ) {
        let cn = format!("{last}.{first}.{mi}.{digits}");
        let edipi = extract_edipi_from_cn(&cn).unwrap();
        prop_assert_eq!(edipi.as_str(), digits.as_str());
    }

    /// Arbitrary bytes fed to `ParsedCertificate::from_der()` must never panic.
    /// Malformed DER input must return `Err`, not crash.
    #[test]
    fn prop_parsed_certificate_from_der_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let _ = ParsedCertificate::from_der(&data);
    }
}
