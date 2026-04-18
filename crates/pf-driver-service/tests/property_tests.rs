// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Property-based tests for `pf-driver-service` IPP parsing.
//!
//! These tests verify that the IPP parser handles arbitrary input safely
//! and that known-good values round-trip correctly.
//!
//! **NIST 800-53 Rev 5:** SI-10 — Information Input Validation

use proptest::prelude::*;

use pf_driver_service::ipp_parser::{
    parse_ipp_request, AttributeGroupTag, IppOperation, ValueTag,
};

proptest! {
    /// Arbitrary bytes fed to `parse_ipp_request()` must never panic.
    /// The function must always return either `Ok` or `Err`.
    #[test]
    fn prop_ipp_parser_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_ipp_request(&data);
    }

    /// Valid IPP operation IDs round-trip through `from_id()` and `id()`.
    #[test]
    fn prop_ipp_operation_id_roundtrip(
        op_id in prop_oneof![
            Just(0x0002u16),
            Just(0x0004u16),
            Just(0x0005u16),
            Just(0x0006u16),
            Just(0x0008u16),
            Just(0x000Au16),
            Just(0x000Bu16),
        ]
    ) {
        let op = IppOperation::from_id(op_id).unwrap();
        prop_assert_eq!(op.id(), op_id);
    }

    /// Arbitrary `u8` input to `ValueTag::from_byte()` must never panic —
    /// it must return `Ok` for known tags and `Err` for unknown ones.
    #[test]
    fn prop_value_tag_from_byte_never_panics(byte in any::<u8>()) {
        let _ = ValueTag::from_byte(byte);
    }

    /// Arbitrary `u8` input to `AttributeGroupTag::from_byte()` must never panic.
    #[test]
    fn prop_attribute_group_tag_from_byte_never_panics(byte in any::<u8>()) {
        let _ = AttributeGroupTag::from_byte(byte);
    }
}
