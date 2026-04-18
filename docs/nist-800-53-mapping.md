# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

# NIST 800-53 Rev 5 — Control-to-Code Traceability Matrix

This document maps NIST 800-53 Rev 5 Moderate baseline controls to their implementing
code in the PrintForge codebase. Every entry includes the crate, module, test prefix,
and commit convention for traceability.

## How to Use This Matrix

1. **Developers:** When implementing a security control, find the row in this matrix,
   implement in the specified crate/module, write tests with the specified prefix,
   and reference the control ID in your commit footer (`NIST-800-53: XX-Y`).

2. **Auditors:** Each control's "Evidence" column points to automated tests that
   serve as continuous compliance evidence. Run `cargo nextest run -E 'test(nist_)'`
   to execute all NIST evidence tests.

3. **eMASS:** The `pf-audit` crate generates eMASS-formatted evidence artifacts
   on demand via the `/api/v1/audit/nist-evidence` endpoint.

## Access Control (AC)

| ID | Control | Crate | Module | Test Prefix | Commit Scope |
|----|---------|-------|--------|-------------|-------------|
| AC-2 | Account Management | pf-user-provisioning | provisioning.rs, scim.rs | nist_ac2_ | sec(user-provisioning) |
| AC-3 | Access Enforcement | pf-api-gateway | rbac.rs, middleware.rs | nist_ac3_ | sec(api-gateway) |
| AC-7 | Unsuccessful Logon Attempts | pf-auth | pin.rs, lockout.rs | nist_ac7_ | sec(auth) |
| AC-8 | System Use Notification | pf-enroll-portal | banner.rs | nist_ac8_ | sec(enroll-portal) |
| AC-17 | Remote Access | pf-api-gateway | tls.rs, mtls.rs | nist_ac17_ | sec(api-gateway) |

## Audit and Accountability (AU)

| ID | Control | Crate | Module | Test Prefix | Commit Scope |
|----|---------|-------|--------|-------------|-------------|
| AU-2 | Event Logging | pf-audit | event_catalog.rs | nist_au2_ | sec(audit) |
| AU-3 | Content of Audit Records | pf-common | audit.rs | nist_au3_ | sec(common) |
| AU-6 | Audit Record Review | pf-audit | siem_export.rs | nist_au6_ | sec(audit) |
| AU-9 | Protection of Audit Info | pf-audit | repository.rs | nist_au9_ | sec(audit) |
| AU-12 | Audit Record Generation | pf-common | audit.rs (trait) | nist_au12_ | sec(common) |

## Identification and Authentication (IA)

| ID | Control | Crate | Module | Test Prefix | Commit Scope |
|----|---------|-------|--------|-------------|-------------|
| IA-2 | Identification and Authentication | pf-auth | oidc.rs, saml.rs, certificate.rs | nist_ia2_ | sec(auth) |
| IA-2(12) | Accept PIV Credentials | pf-auth | certificate.rs | nist_ia2_12_ | sec(auth) |
| IA-5 | Authenticator Management | pf-auth | certificate.rs, ocsp.rs, crl.rs | nist_ia5_ | sec(auth) |
| IA-5(2) | PKI-Based Authentication | pf-auth | trust_store.rs | nist_ia5_2_ | sec(auth) |
| IA-8 | Non-Organizational Users | pf-auth | oidc.rs, saml.rs | nist_ia8_ | sec(auth) |

## System and Communications Protection (SC)

| ID | Control | Crate | Module | Test Prefix | Commit Scope |
|----|---------|-------|--------|-------------|-------------|
| SC-8 | Transmission Confidentiality | pf-api-gateway, pf-driver-service | tls.rs | nist_sc8_ | sec(api-gateway) |
| SC-12 | Cryptographic Key Management | pf-spool | key_store.rs, encryption.rs | nist_sc12_ | sec(spool) |
| SC-13 | Cryptographic Protection | pf-common | crypto.rs | nist_sc13_ | sec(common) |
| SC-17 | PKI Certificates | pf-auth | trust_store.rs | nist_sc17_ | sec(auth) |
| SC-28 | Protection of Info at Rest | pf-spool | encryption.rs | nist_sc28_ | sec(spool) |

## System and Information Integrity (SI)

| ID | Control | Crate | Module | Test Prefix | Commit Scope |
|----|---------|-------|--------|-------------|-------------|
| SI-2 | Flaw Remediation | CI pipeline | ci.yaml (cargo audit) | — | ci(ci) |
| SI-10 | Information Input Validation | pf-common | validated.rs | nist_si10_ | sec(common) |
| SI-11 | Error Handling | pf-common | error.rs | nist_si11_ | sec(common) |

## Running NIST Evidence Tests

```bash
# Run ALL NIST compliance evidence tests
cargo nextest run -E 'test(nist_)'

# Run tests for a specific control family
cargo nextest run -E 'test(nist_ia)'    # Identification & Authentication
cargo nextest run -E 'test(nist_sc)'    # System & Communications Protection
cargo nextest run -E 'test(nist_au)'    # Audit & Accountability
cargo nextest run -E 'test(nist_ac)'    # Access Control
cargo nextest run -E 'test(nist_si)'    # System & Information Integrity
```
