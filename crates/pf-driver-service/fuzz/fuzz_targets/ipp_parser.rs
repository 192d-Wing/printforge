// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Fuzz target for IPP message parsing.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation
//!
//! Feeds arbitrary bytes into `parse_ipp_request()` and ensures the parser
//! never panics — it must always return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pf_driver_service::ipp_parser::parse_ipp_request;

fuzz_target!(|data: &[u8]| {
    // The parser must handle any input without panicking.
    // We deliberately ignore the result — we only care that it does not crash.
    let _ = parse_ipp_request(data);
});
