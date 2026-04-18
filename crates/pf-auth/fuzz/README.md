# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# Fuzz Testing — pf-auth

Fuzz targets for X.509 certificate parsing (DER and PEM formats).
These parsers handle untrusted input from CAC/PIV smart cards and TLS
client certificates.

**NIST 800-53 Rev 5:** IA-5(2) — PKI-Based Authentication

## Prerequisites

```bash
# Install cargo-fuzz (requires nightly toolchain)
rustup install nightly
cargo +nightly install cargo-fuzz
```

## Generate Seed Corpus

Before the first fuzzing session, generate seed certificates:

```bash
pip install cryptography   # if not already installed
python3 crates/pf-auth/fuzz/generate_corpus.py
```

This creates self-signed test certificates in DER and PEM format that give
the fuzzer a starting point. The fuzzer works without seeds, but coverage
ramp-up will be slower.

## Targets

### certificate_parser

Feeds arbitrary bytes into `ParsedCertificate::from_der()` and asserts it
never panics.

```bash
cargo +nightly fuzz run certificate_parser -- -max_len=65536
```

### pem_parser

Feeds arbitrary bytes into `ParsedCertificate::from_pem()` and asserts it
never panics.

```bash
cargo +nightly fuzz run pem_parser -- -max_len=65536
```

## Running All Targets

```bash
# Run each target for 5 minutes
for target in certificate_parser pem_parser; do
    cargo +nightly fuzz run "$target" -- -max_len=65536 -max_total_time=300
done
```

## Interpreting Results

If the fuzzer finds a crash, it saves the input to
`fuzz/artifacts/<target>/`. Reproduce with:

```bash
cargo +nightly fuzz run certificate_parser fuzz/artifacts/certificate_parser/<crash-file>
cargo +nightly fuzz run pem_parser fuzz/artifacts/pem_parser/<crash-file>
```

Minimize a crash input:

```bash
cargo +nightly fuzz tmin certificate_parser fuzz/artifacts/certificate_parser/<crash-file>
```

## Coverage

```bash
cargo +nightly fuzz coverage certificate_parser
cargo +nightly fuzz coverage pem_parser
```
