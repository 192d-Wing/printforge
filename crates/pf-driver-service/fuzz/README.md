# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Fuzz Testing — pf-driver-service

Fuzz targets for the IPP message parser, which handles untrusted network input.

**NIST 800-53 Rev 5:** SI-10 — Information Input Validation

## Prerequisites

```bash
# Install cargo-fuzz (requires nightly toolchain)
rustup install nightly
cargo +nightly install cargo-fuzz
```

## Generate Seed Corpus

Before the first fuzzing session, generate binary seed corpus files:

```bash
python3 crates/pf-driver-service/fuzz/generate_corpus.py
```

This creates minimal valid IPP requests (Print-Job, Get-Printer-Attributes)
that give the fuzzer a head start on exploring valid parser paths.

## Targets

### ipp_parser

Feeds arbitrary bytes into `parse_ipp_request()` and asserts it never panics.

```bash
# Run indefinitely (press Ctrl-C to stop)
cargo +nightly fuzz run ipp_parser -- -max_len=65536

# Run for a fixed number of iterations
cargo +nightly fuzz run ipp_parser -- -max_len=65536 -runs=1000000

# Run with multiple jobs (parallel fuzzing)
cargo +nightly fuzz run ipp_parser -- -max_len=65536 -jobs=4 -workers=4
```

## Interpreting Results

If the fuzzer finds a crash, it saves the input to `fuzz/artifacts/ipp_parser/`.
Reproduce a crash with:

```bash
cargo +nightly fuzz run ipp_parser fuzz/artifacts/ipp_parser/<crash-file>
```

Minimize a crash input:

```bash
cargo +nightly fuzz tmin ipp_parser fuzz/artifacts/ipp_parser/<crash-file>
```

## Coverage

Generate a coverage report to see which parser paths have been exercised:

```bash
cargo +nightly fuzz coverage ipp_parser
```
