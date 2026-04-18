// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fuzz target for PEM-encoded X.509 certificate parsing.
//!
//! **NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication
//!
//! Feeds arbitrary bytes into `ParsedCertificate::from_pem()` and ensures the
//! parser never panics — it must always return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pf_auth::ParsedCertificate;

fuzz_target!(|data: &[u8]| {
    // The parser must handle any input without panicking.
    // We deliberately ignore the result — we only care that it does not crash.
    let _ = ParsedCertificate::from_pem(data);
});
