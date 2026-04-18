<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PrintForge Contributors -->

# PrintForge STRIDE Threat Model

**Version:** 1.0
**Date:** 2026-04-04
**Classification:** CUI // SP-INFOSEC
**Scope:** All PrintForge components across NIPR and SIPR enclaves

---

## 1. System Overview

PrintForge is an enterprise print management platform for the Department of the Air Force (DAF), deployed across 184 installations on both NIPR and SIPR enclaves. The platform provides Follow-Me secure printing, multi-vendor fleet management, cost accounting, and supply chain automation.

### 1.1 Architecture Summary

PrintForge is a Rust multi-crate workspace deployed as OCI containers on Kubernetes:

- **Central Management Plane (RKE2):** Hosts the API gateway, authentication services, job queue, policy engine, accounting, audit, fleet management, firmware management, supply automation, admin UI backend, and enrollment portal backend.
- **Edge Cache Nodes (K3s):** Deployed at each DAF installation. Each cache node embeds local instances of the job queue, spool store (RustFS), auth cache, fleet proxy, and IPPS driver service. Operates autonomously during WAN outages (DDIL mode).
- **Data Stores:** PostgreSQL (job metadata, user records, audit logs, inventory), TimescaleDB (printer telemetry), RustFS (encrypted spool data), HashiCorp Vault (KEK storage), NATS (inter-node messaging).

### 1.2 Data Flow Summary

1. **Job Submission:** User workstation sends print job via IPPS (TLS) to the driver service, which validates IPP attributes, evaluates policies, encrypts spool data, and holds the job.
2. **Job Release:** User authenticates at a printer panel (CAC/PIV), the system retrieves their held jobs, the user selects a job, spool data is decrypted and delivered to the printer via IPPS.
3. **Fleet Management:** SNMPv3 polling collects printer status, supply levels, and page counts. Data feeds alerting, supply reorder, and firmware management.
4. **User Provisioning:** Users authenticate via OIDC (NIPR) or SAML (SIPR). JIT provisioning creates accounts on first login. SCIM 2.0 supports bulk provisioning from Entra ID.
5. **Edge Sync:** Cache nodes maintain a NATS leaf connection to the central plane. During DDIL mode, operations continue locally and sync on reconnect via vector clocks.

---

## 2. Trust Boundaries

The following trust boundaries define the security perimeter and internal segmentation of the PrintForge platform.

### TB-1: Network Perimeter (Enclave Boundary)

| Property | Description |
|---|---|
| **Boundary** | NIPR/SIPR enclave network perimeter |
| **Crosses** | All external traffic entering or leaving the enclave |
| **Controls** | Enclave firewalls, IDS/IPS, DISA STIG-hardened network infrastructure |
| **PrintForge components** | All components reside inside the enclave boundary |

### TB-2: TLS Termination at API Gateway

| Property | Description |
|---|---|
| **Boundary** | External clients (browsers, SCIM clients) to `pf-api-gateway` |
| **Crosses** | All HTTP/gRPC API traffic |
| **Controls** | TLS 1.3 (external), JWT authentication, RBAC authorization, rate limiting, input validation |
| **Relevant crates** | `pf-api-gateway` (tls.rs, middleware/auth.rs, middleware/rbac.rs, middleware/rate_limit.rs, validation.rs) |

### TB-3: mTLS Service Mesh

| Property | Description |
|---|---|
| **Boundary** | Between internal microservices on the central plane |
| **Crosses** | Service-to-service calls (API gateway to backend crates, OPA sidecar communication) |
| **Controls** | mTLS with client certificate validation, TLS 1.2+ |
| **Relevant crates** | `pf-api-gateway` (mtls.rs), `pf-policy-engine` (client.rs) |

### TB-4: IPPS Ingestion Boundary

| Property | Description |
|---|---|
| **Boundary** | User workstations to `pf-driver-service` IPPS endpoint |
| **Crosses** | Print job submissions (document data + IPP attributes) |
| **Controls** | IPPS (TLS 1.2+), IPP attribute sanitization, document format validation, size limits, optional mTLS |
| **Relevant crates** | `pf-driver-service` (tls.rs, ipp_parser.rs, attributes.rs, hold.rs) |

### TB-5: DDIL Boundary (Central-to-Edge)

| Property | Description |
|---|---|
| **Boundary** | Central management plane to edge cache nodes at each installation |
| **Crosses** | Job sync, auth cache updates, fleet telemetry, audit event replication |
| **Controls** | NATS TLS with mTLS, vector clock sync, central-wins conflict resolution, heartbeat monitoring |
| **Relevant crates** | `pf-cache-node` (nats_leaf.rs, sync.rs, heartbeat.rs, auth_cache.rs) |

### TB-6: Printer Management Network

| Property | Description |
|---|---|
| **Boundary** | PrintForge services to managed printers |
| **Crosses** | SNMPv3 polling, IPPS job delivery, firmware updates |
| **Controls** | SNMPv3 AuthPriv (SHA-256/AES-128), IPPS for job delivery, firmware signature validation |
| **Relevant crates** | `pf-fleet-mgr` (snmp.rs, discovery.rs), `pf-job-queue` (delivery.rs), `pf-firmware-mgr` (deployment.rs) |

### TB-7: Identity Provider Boundary

| Property | Description |
|---|---|
| **Boundary** | PrintForge to external identity providers (Entra ID, DISA E-ICAM) |
| **Crosses** | OIDC authorization code flows, SAML assertions, SCIM provisioning, OCSP/CRL requests |
| **Controls** | OIDC PKCE, SAML signature validation, SCIM bearer token auth, TLS for all IdP communication |
| **Relevant crates** | `pf-auth` (oidc.rs, saml.rs, ocsp.rs, crl.rs), `pf-enroll-portal` (idp_redirect.rs, callback.rs) |

### TB-8: External Vendor API Boundary

| Property | Description |
|---|---|
| **Boundary** | PrintForge to vendor APIs (HP, Xerox, Lexmark, Konica Minolta supply ordering; firmware feeds) |
| **Crosses** | Supply reorder requests, firmware downloads |
| **Controls** | TLS, API key authentication (stored as `Secret<String>`), available only on NIPR |
| **Relevant crates** | `pf-supply` (vendor_hp.rs, vendor_xerox.rs, vendor_lexmark.rs, vendor_km.rs), `pf-firmware-mgr` (acquisition.rs) |

---

## 3. STRIDE Threat Analysis

### 3.1 Spoofing

Threats where an attacker assumes the identity of another entity.

| ID | Threat | Target Component | Trust Boundary | Likelihood | Impact | Risk |
|----|--------|-----------------|----------------|------------|--------|------|
| S-1 | Stolen CAC/PIV used to authenticate and release another user's held print jobs | `pf-auth` (certificate.rs) | TB-2, TB-4 | Medium | High | High |
| S-2 | JWT replay attack: captured JWT used to impersonate authenticated user | `pf-auth` (jwt.rs), `pf-api-gateway` (middleware/auth.rs) | TB-2 | Medium | High | High |
| S-3 | SAML assertion forgery or XML signature wrapping attack | `pf-auth` (saml.rs) | TB-7 | Low | Critical | High |
| S-4 | OIDC authorization code interception (code injection attack) | `pf-auth` (oidc.rs), `pf-enroll-portal` (callback.rs) | TB-7 | Low | High | Medium |
| S-5 | IPP `requesting-user-name` spoofing: client claims to be a different user | `pf-driver-service` (attributes.rs) | TB-4 | High | Medium | High |
| S-6 | Rogue cache node impersonates a legitimate edge node to the central plane | `pf-cache-node` (nats_leaf.rs) | TB-5 | Low | Critical | Medium |
| S-7 | Compromised SCIM client submits fraudulent provisioning requests | `pf-user-provisioning` (scim/endpoints.rs) | TB-2 | Low | High | Medium |
| S-8 | Spoofed SNMPv3 responses from a rogue device impersonating a managed printer | `pf-fleet-mgr` (snmp.rs) | TB-6 | Low | Medium | Low |

**Mitigations:**

| Threat | Mitigation | NIST Control | Implementing Crate/Module | Evidence Test Prefix |
|--------|-----------|-------------|--------------------------|---------------------|
| S-1 | Full X.509 chain validation against DoD/NSS PKI trust anchors; OCSP/CRL revocation checking before JWT issuance; PIN failure lockout after configurable attempts | IA-2, IA-5, IA-5(2), AC-7 | `pf-auth` (certificate.rs, ocsp.rs, crl.rs, trust_store.rs, pin.rs) | `nist_ia2_`, `nist_ia5_`, `nist_ac7_` |
| S-2 | Short-lived JWTs (15 min printer-scoped, 1 hr web session); Ed25519 signing via `ring`; server-side refresh token storage; revocation cache checked on every request | IA-5, SC-12 | `pf-auth` (jwt.rs), `pf-api-gateway` (middleware/auth.rs) | `nist_ia5_` |
| S-3 | SAML assertion signature validation; InResponseTo validation; assertion expiry enforcement | IA-2, IA-8 | `pf-auth` (saml.rs) | `nist_ia2_` |
| S-4 | OIDC Authorization Code Flow with PKCE (S256); state parameter validation (CSRF protection) | IA-2, IA-8 | `pf-auth` (oidc.rs), `pf-enroll-portal` (callback.rs) | `nist_ia2_` |
| S-5 | When mTLS is enabled, client certificate identity is cross-referenced against `requesting-user-name`; without mTLS, the `requesting-user-name` alone is not treated as a trusted identity | IA-2, SI-10 | `pf-driver-service` (attributes.rs, tls.rs) | `nist_ia2_`, `nist_si10_` |
| S-6 | mTLS required for NATS leaf connections; cache node client certificates issued per-installation | SC-8 | `pf-cache-node` (nats_leaf.rs) | `nist_sc8_` |
| S-7 | SCIM endpoint authenticates callers via bearer token (Entra ID service principal); tokens stored as `Secret<String>` | AC-2, IA-8 | `pf-user-provisioning` (scim/endpoints.rs) | `nist_ac2_` |
| S-8 | SNMPv3 AuthPriv mode (SHA-256 auth, AES-128 privacy); discovery scans restricted to configured subnets | CM-8 | `pf-fleet-mgr` (snmp.rs, discovery.rs) | `nist_cm8_` |

---

### 3.2 Tampering

Threats where an attacker modifies data in transit or at rest.

| ID | Threat | Target Component | Trust Boundary | Likelihood | Impact | Risk |
|----|--------|-----------------|----------------|------------|--------|------|
| T-1 | Spool data modified in RustFS (document content altered before printing) | `pf-spool` (encryption.rs, spool.rs) | At rest | Low | High | Medium |
| T-2 | Firmware image tampered with during download or storage (malicious firmware deployed to printers) | `pf-firmware-mgr` (acquisition.rs, validation.rs) | TB-8, at rest | Low | Critical | High |
| T-3 | Audit log records modified or deleted to cover unauthorized activity | `pf-audit` (repository.rs, writer.rs) | At rest | Low | Critical | Medium |
| T-4 | Policy (Rego) files tampered with to bypass quota or access controls | `pf-policy-engine` (policies/) | At rest | Low | High | Medium |
| T-5 | NATS messages tampered with during central-to-edge sync, causing data corruption | `pf-cache-node` (nats_leaf.rs, sync.rs) | TB-5 | Low | High | Medium |
| T-6 | Job metadata altered in PostgreSQL to change cost center assignment or page counts | `pf-accounting` (repository.rs) | At rest | Low | Medium | Low |
| T-7 | IPP attributes manipulated in transit to bypass policy evaluation | `pf-driver-service` (ipp_parser.rs) | TB-4 | Low | Medium | Low |
| T-8 | Trust store file replaced with attacker-controlled CA certificates | `pf-auth` (trust_store.rs) | At rest | Low | Critical | Medium |

**Mitigations:**

| Threat | Mitigation | NIST Control | Implementing Crate/Module | Evidence Test Prefix |
|--------|-----------|-------------|--------------------------|---------------------|
| T-1 | AES-256-GCM encryption with per-job DEK; GCM provides authenticated encryption (integrity + confidentiality); DEKs wrapped by KEK from Vault | SC-28, SC-12, SC-13 | `pf-spool` (encryption.rs, key_store.rs) | `nist_sc28_`, `nist_sc12_` |
| T-2 | SHA-256 checksum validation; code-signing signature verification; firmware stored in OCI registry; Fleet Admin approval gate before deployment | SI-7, SI-2, CM-3 | `pf-firmware-mgr` (validation.rs, approval.rs, registry.rs) | `nist_si7_` |
| T-3 | Append-only PostgreSQL audit table; `REVOKE UPDATE, DELETE ON audit_events FROM printforge_app`; separate DB role for archive operations only | AU-9 | `pf-audit` (repository.rs, writer.rs) | `nist_au9_` |
| T-4 | Rego policies version-controlled in the repository; changes require PR review; policy-as-code through standard CI pipeline | CM-3, AC-3 | `pf-policy-engine` (policies/) | `nist_ac3_` |
| T-5 | NATS TLS with mTLS for transport integrity; vector clock sync with central-wins conflict resolution prevents stale data overwrite | SC-8 | `pf-cache-node` (nats_leaf.rs, sync.rs) | `nist_sc8_` |
| T-6 | Quota counters use `SELECT FOR UPDATE` for transactional integrity; cost assignment is audited; financial data subject to 7-year retention | AU-12 | `pf-accounting` (repository.rs, quota.rs) | `nist_au12_` |
| T-7 | IPPS (TLS 1.2+) provides transport integrity; all IPP attributes re-validated server-side regardless of transport | SC-8, SI-10 | `pf-driver-service` (tls.rs, attributes.rs, ipp_parser.rs) | `nist_sc8_`, `nist_si10_` |
| T-8 | Trust store loading fails closed (missing or unparseable file rejects all certificate authentication); file permissions restricted to service account | IA-5(2), SC-17 | `pf-auth` (trust_store.rs) | `nist_ia5_2_` |

---

### 3.3 Repudiation

Threats where an actor denies performing an action.

| ID | Threat | Target Component | Trust Boundary | Likelihood | Impact | Risk |
|----|--------|-----------------|----------------|------------|--------|------|
| R-1 | User denies submitting a print job (no audit trail linking user to job) | `pf-job-queue`, `pf-audit` | TB-4 | Medium | Medium | Medium |
| R-2 | Administrator denies modifying a print policy or quota override | `pf-policy-engine`, `pf-audit` | TB-2 | Low | High | Medium |
| R-3 | User denies releasing a job at a specific printer (claims they were elsewhere) | `pf-job-queue`, `pf-auth`, `pf-audit` | TB-2 | Medium | Medium | Medium |
| R-4 | SCIM provisioning actions not attributable to a specific service principal | `pf-user-provisioning`, `pf-audit` | TB-2 | Low | Medium | Low |
| R-5 | Firmware deployment not traceable to the approving administrator | `pf-firmware-mgr`, `pf-audit` | TB-2 | Low | High | Medium |
| R-6 | Supply reorder approved without traceable authorization | `pf-supply`, `pf-audit` | TB-2 | Low | Medium | Low |

**Mitigations:**

| Threat | Mitigation | NIST Control | Implementing Crate/Module | Evidence Test Prefix |
|--------|-----------|-------------|--------------------------|---------------------|
| R-1 | Every job state transition emits a structured audit event (JOB_SUBMITTED, JOB_HELD, etc.) with actor EDIPI, timestamp, source IP; CAC/PIV authentication provides strong identity binding | AU-2, AU-3, AU-12, IA-2 | `pf-audit` (event_catalog.rs, collector.rs), `pf-job-queue` (lifecycle.rs) | `nist_au2_`, `nist_au3_`, `nist_au12_` |
| R-2 | POLICY_MODIFY audit events include actor EDIPI, previous and new policy state; append-only audit log prevents after-the-fact modification | AU-2, AU-9 | `pf-audit` (event_catalog.rs, repository.rs), `pf-policy-engine` | `nist_au2_`, `nist_au9_` |
| R-3 | JOB_RELEASED event records EDIPI, printer ID, timestamp, and source IP (printer panel network address); CAC authentication at printer provides physical presence evidence | AU-3, IA-2 | `pf-audit` (event_catalog.rs), `pf-auth` (certificate.rs) | `nist_au3_`, `nist_ia2_` |
| R-4 | SCIM endpoints log the authenticated service principal in USER_CREATED/USER_UPDATED events; bearer token identifies the calling system | AU-12, AC-2 | `pf-user-provisioning` (scim/endpoints.rs), `pf-audit` | `nist_au12_`, `nist_ac2_` |
| R-5 | FIRMWARE_APPROVED event records the approving Fleet Admin EDIPI; approval is a mandatory gate before deployment | AU-2, CM-3 | `pf-firmware-mgr` (approval.rs), `pf-audit` | `nist_au2_` |
| R-6 | REORDER_APPROVED event records the approving administrator; orders above threshold require explicit Site/Fleet Admin approval | AU-12 | `pf-supply` (approval.rs), `pf-audit` | `nist_au12_` |

---

### 3.4 Information Disclosure

Threats where sensitive data is exposed to unauthorized parties.

| ID | Threat | Target Component | Trust Boundary | Likelihood | Impact | Risk |
|----|--------|-----------------|----------------|------------|--------|------|
| I-1 | CUI document content leaked via unencrypted spool data at rest | `pf-spool` | At rest | Low | Critical | High |
| I-2 | PII (EDIPIs, names) leaked in API error responses or log output | `pf-api-gateway`, `pf-common` | TB-2 | Medium | High | High |
| I-3 | Print job content exposed during transit between services (unencrypted internal traffic) | `pf-job-queue`, `pf-spool` | TB-3 | Low | High | Medium |
| I-4 | SNMPv3 credentials (auth/privacy keys) leaked in logs or debug output | `pf-fleet-mgr` (snmp.rs) | TB-6 | Medium | High | High |
| I-5 | JWT signing keys exposed via debug output, error messages, or core dumps | `pf-auth` (jwt.rs) | At rest | Low | Critical | Medium |
| I-6 | Audit log contents accessible to unauthorized users (PII in audit records) | `pf-audit` (query.rs) | TB-2 | Low | High | Medium |
| I-7 | Cross-cost-center data leakage in accounting reports | `pf-accounting` (reporting.rs, chargeback.rs) | TB-2 | Medium | Medium | Medium |
| I-8 | Vendor API keys leaked in logs or serialized configuration | `pf-supply` (vendor_*.rs) | TB-8 | Medium | Medium | Medium |
| I-9 | Cached OCSP responses or cert-to-EDIPI mappings exposed on compromised cache node | `pf-cache-node` (auth_cache.rs) | TB-5 | Low | Medium | Low |
| I-10 | Printer IP addresses and serial numbers (CUI) exposed in public API responses | `pf-fleet-mgr` (inventory.rs) | TB-2 | Medium | Medium | Medium |

**Mitigations:**

| Threat | Mitigation | NIST Control | Implementing Crate/Module | Evidence Test Prefix |
|--------|-----------|-------------|--------------------------|---------------------|
| I-1 | AES-256-GCM per-job encryption; encryption is mandatory (no unencrypted path); DEK/KEK hierarchy with KEK in Vault | SC-28, SC-12, SC-13 | `pf-spool` (encryption.rs, key_store.rs) | `nist_sc28_`, `nist_sc12_`, `nist_sc13_` |
| I-2 | Sanitized error responses (generic messages with request ID only); `thiserror` internal variants logged server-side; `Edipi` displays as `***EDIPI***` in logs | SI-11 | `pf-common` (error.rs), `pf-api-gateway` (error.rs) | `nist_si11_` |
| I-3 | mTLS between all internal services; TLS 1.2+ for all internal communication | SC-8 | `pf-api-gateway` (mtls.rs) | `nist_sc8_` |
| I-4 | SNMPv3 credentials stored as `secrecy::Secret<String>`; redacted in Debug/Display output; never serialized to logs | SC-13 | `pf-fleet-mgr` (config.rs, snmp.rs) | `nist_sc13_` |
| I-5 | JWT signing keys stored as `secrecy::Secret<String>`; never logged or included in error messages | SC-12 | `pf-auth` (jwt.rs) | `nist_sc12_` |
| I-6 | Audit query API restricted to Auditor role via RBAC; PII limited to EDIPI in audit records (full names resolved in UI layer) | AU-6, AC-3 | `pf-audit` (query.rs), `pf-api-gateway` (middleware/rbac.rs) | `nist_au6_`, `nist_ac3_` |
| I-7 | Accounting API scoped to requesting user's cost centers; Fleet Admin/Auditor role required for cross-cost-center access | AC-3 | `pf-accounting` (reporting.rs, chargeback.rs) | `nist_ac3_` |
| I-8 | Vendor API keys stored as `secrecy::Secret<String>`; never logged or serialized | SC-13 | `pf-supply` (config.rs, vendor_*.rs) | `nist_sc13_` |
| I-9 | Auth cache TTL configurable (default 4h); cached OCSP responses validated (signature check) before use; local RustFS encrypted at rest | IA-5, SC-28 | `pf-cache-node` (auth_cache.rs, local_spool.rs) | `nist_ia5_` |
| I-10 | Printer inventory API requires authorization; IP addresses and serial numbers treated as CUI; not exposed without SiteAdmin/FleetAdmin role | AC-3, CM-8 | `pf-fleet-mgr` (inventory.rs), `pf-api-gateway` (middleware/rbac.rs) | `nist_ac3_` |

---

### 3.5 Denial of Service

Threats where an attacker disrupts the availability of the system.

| ID | Threat | Target Component | Trust Boundary | Likelihood | Impact | Risk |
|----|--------|-----------------|----------------|------------|--------|------|
| D-1 | Print queue flooding: mass job submission to exhaust spool storage | `pf-driver-service`, `pf-job-queue`, `pf-spool` | TB-4 | Medium | High | High |
| D-2 | API rate limit bypass: automated requests overwhelm the API gateway | `pf-api-gateway` (middleware/rate_limit.rs) | TB-2 | Medium | High | High |
| D-3 | SNMPv3 polling storm: misconfigured or excessive polling overwhelms printers or network | `pf-fleet-mgr` (snmp.rs) | TB-6 | Low | Medium | Low |
| D-4 | NATS message storm: excessive sync messages between central and edge nodes | `pf-cache-node` (nats_leaf.rs, sync.rs) | TB-5 | Low | Medium | Low |
| D-5 | Spool storage exhaustion: retained jobs fill RustFS capacity | `pf-spool` (retention.rs) | At rest | Medium | High | Medium |
| D-6 | OCSP/CRL responder unavailability blocks all certificate-based authentication | `pf-auth` (ocsp.rs, crl.rs) | TB-7 | Medium | High | High |
| D-7 | Malformed IPP messages cause parser resource exhaustion or crash | `pf-driver-service` (ipp_parser.rs) | TB-4 | Medium | Medium | Medium |
| D-8 | Database connection exhaustion from concurrent job submissions | `pf-job-queue` (repository.rs) | Internal | Low | High | Medium |
| D-9 | Firmware rollout overwhelms printer fleet with simultaneous updates | `pf-firmware-mgr` (rollout.rs) | TB-6 | Low | High | Medium |

**Mitigations:**

| Threat | Mitigation | NIST Control | Implementing Crate/Module | Evidence Test Prefix |
|--------|-----------|-------------|--------------------------|---------------------|
| D-1 | Maximum job size enforced (default 100 MB); policy evaluation before spool storage (reject early); per-user quota enforcement | SI-10, AC-3 | `pf-driver-service` (config.rs), `pf-policy-engine` (quota.rs), `pf-accounting` (quota.rs) | `nist_si10_`, `nist_ac3_` |
| D-2 | Token-bucket rate limiter per client IP and per user; configurable rates per route group; 429 response with Retry-After header | SC-5 (implicit) | `pf-api-gateway` (middleware/rate_limit.rs) | N/A |
| D-3 | Configurable poll intervals (status 60s, supply 5min, telemetry 15min); discovery scans restricted to configured subnets | CM-8, SI-4 | `pf-fleet-mgr` (config.rs, discovery.rs, snmp.rs) | N/A |
| D-4 | NATS leaf node configurable max buffer (256 MB); buffered replay is ordered and throttled | SC-8 | `pf-cache-node` (nats_leaf.rs, config.rs) | N/A |
| D-5 | Retention auto-purge runs every 5 minutes; configurable per-policy retention windows; job purge deletes S3 object and zeroes DEK | SC-28 | `pf-spool` (retention.rs) | `nist_sc28_` |
| D-6 | OCSP response caching with configurable TTL (default 4h); CRL fallback when OCSP is unavailable; cache node operates on cached OCSP during DDIL | IA-5 | `pf-auth` (ocsp.rs, crl.rs), `pf-cache-node` (auth_cache.rs) | `nist_ia5_` |
| D-7 | IPP attribute validation with strict type and range checking; malformed attributes logged and ignored; fuzz testing target for IPP parser; request body size limits | SI-10 | `pf-driver-service` (ipp_parser.rs, attributes.rs) | `nist_si10_` |
| D-8 | Connection pooling via sqlx; bounded concurrency in Tokio runtime | N/A | `pf-job-queue` (repository.rs) | N/A |
| D-9 | Phased rollout (5%/72h, 25%/48h, 100%); auto-halt on anomaly (error rate > baseline + 2 sigma) | CM-3 | `pf-firmware-mgr` (rollout.rs, monitoring.rs) | N/A |

---

### 3.6 Elevation of Privilege

Threats where an attacker gains unauthorized access to higher-privilege operations.

| ID | Threat | Target Component | Trust Boundary | Likelihood | Impact | Risk |
|----|--------|-----------------|----------------|------------|--------|------|
| E-1 | JWT claim manipulation: user modifies role claims in a forged or tampered JWT | `pf-auth` (jwt.rs), `pf-api-gateway` (middleware/auth.rs) | TB-2 | Medium | Critical | High |
| E-2 | RBAC bypass: API routes missing `RequireRole` middleware allow unauthorized access | `pf-api-gateway` (router.rs, middleware/rbac.rs) | TB-2 | Medium | Critical | High |
| E-3 | Policy bypass: OPA failure mode allows jobs that should be denied | `pf-policy-engine` (client.rs, embedded.rs) | TB-3 | Low | High | Medium |
| E-4 | IdP group-to-role mapping exploited to gain FleetAdmin or Auditor role | `pf-user-provisioning` (role_mapping.rs) | TB-7 | Low | Critical | Medium |
| E-5 | SCIM bulk operation used to elevate a user's role without proper authorization | `pf-user-provisioning` (scim/bulk.rs) | TB-2 | Low | High | Medium |
| E-6 | Cross-tenant access: SiteAdmin at one installation accesses another installation's data | `pf-admin-ui` (scope.rs), `pf-api-gateway` | TB-2 | Medium | High | High |
| E-7 | Cache node compromise grants access to all locally cached credentials and spool data | `pf-cache-node` | TB-5 | Low | Critical | Medium |
| E-8 | Direct database access bypasses application-level RBAC | PostgreSQL | Internal | Low | Critical | Medium |

**Mitigations:**

| Threat | Mitigation | NIST Control | Implementing Crate/Module | Evidence Test Prefix |
|--------|-----------|-------------|--------------------------|---------------------|
| E-1 | JWTs signed with Ed25519 via `ring`; signature verified on every request; role claims are server-authoritative (derived from database, not from client-provided claims); short token lifetime | IA-5, SC-12 | `pf-auth` (jwt.rs), `pf-api-gateway` (middleware/auth.rs) | `nist_ia5_`, `nist_sc12_` |
| E-2 | Every route MUST have `RequireAuth` or be explicitly listed in public allowlist (`/healthz`, `/readyz`, `/api/v1/enroll/auth`); CI enforcement of route coverage | AC-3 | `pf-api-gateway` (router.rs, middleware/auth.rs, middleware/rbac.rs) | `nist_ac3_` |
| E-3 | Default-deny policy: if OPA is unreachable or returns error, job is HELD (fail closed); OPA communication via mTLS when running as sidecar | AC-3, AC-6 | `pf-policy-engine` (client.rs, embedded.rs) | `nist_ac3_` |
| E-4 | Role mapping table is configured by Fleet Admins through the admin UI (not self-service); role changes are audited with previous and new role; wildcard patterns require explicit approval | AC-2, AU-12 | `pf-user-provisioning` (role_mapping.rs), `pf-audit` | `nist_ac2_`, `nist_au12_` |
| E-5 | SCIM endpoint authenticates the calling service principal; role assignment through SCIM follows the same role mapping rules; all provisioning actions audited | AC-2, AC-2(1) | `pf-user-provisioning` (scim/endpoints.rs, scim/bulk.rs) | `nist_ac2_` |
| E-6 | SiteAdmin role is scoped to a specific `SiteId`; API queries filter data by the authenticated user's site scope; FleetAdmin required for cross-site access | AC-3, AC-6 | `pf-admin-ui` (scope.rs), `pf-api-gateway` (middleware/rbac.rs) | `nist_ac3_` |
| E-7 | Local RustFS data encrypted at rest (same DEK/KEK scheme); auth cache has configurable TTL; NATS mTLS prevents unauthorized sync; K3s node hardened per DISA STIG | SC-28, SC-8 | `pf-cache-node` (local_spool.rs, auth_cache.rs, nats_leaf.rs) | `nist_sc28_`, `nist_sc8_` |
| E-8 | Application database role has least-privilege grants; audit table has UPDATE/DELETE revoked; Kubernetes network policies restrict database access to PrintForge pods | AC-3, AC-6, AU-9 | `pf-audit` (repository.rs), Kubernetes network policies | `nist_ac3_`, `nist_au9_` |

---

## 4. Component Threat Summary

The following table provides a per-component summary of the primary threats and their current mitigation status.

| Component | Primary Threats | Key Mitigations | Status |
|-----------|----------------|-----------------|--------|
| `pf-auth` | S-1 (stolen CAC), S-2 (JWT replay), S-3 (SAML forgery), I-5 (key leak) | Chain validation, OCSP/CRL, PKCE, short-lived JWT, `Secret<>` types | Implemented |
| `pf-api-gateway` | E-2 (RBAC bypass), D-2 (rate limit bypass), I-2 (info leak in errors) | RequireAuth on all routes, rate limiting, sanitized errors | Implemented |
| `pf-driver-service` | S-5 (user spoofing), D-1 (queue flood), D-7 (parser crash) | mTLS cross-reference, size limits, fuzz testing, attribute sanitization | Implemented |
| `pf-spool` | T-1 (spool tampering), I-1 (CUI leak at rest), D-5 (storage exhaustion) | AES-256-GCM per-job encryption, retention auto-purge | Implemented |
| `pf-job-queue` | R-1 (job repudiation), D-1 (queue flooding) | Full lifecycle audit trail, policy evaluation before acceptance | Implemented |
| `pf-audit` | T-3 (log tampering), R-1/R-2/R-3 (repudiation) | Append-only table, REVOKE UPDATE/DELETE, structured JSON | Implemented |
| `pf-cache-node` | S-6 (rogue node), T-5 (sync tampering), E-7 (node compromise) | mTLS NATS, encrypted local spool, central-wins sync | Implemented |
| `pf-fleet-mgr` | S-8 (spoofed SNMP), I-4 (credential leak), D-3 (poll storm) | SNMPv3 AuthPriv, `Secret<>` types, configurable intervals | Implemented |
| `pf-firmware-mgr` | T-2 (firmware tampering), D-9 (rollout overload) | Checksum + signature validation, phased rollout, approval gate | Implemented |
| `pf-policy-engine` | E-3 (policy bypass), T-4 (Rego tampering) | Default-deny, fail closed, policy-as-code in VCS | Implemented |
| `pf-user-provisioning` | S-7 (fraudulent SCIM), E-4 (role escalation), E-5 (bulk role inject) | SCIM auth, role mapping config by Fleet Admin, audit trail | Implemented |
| `pf-accounting` | T-6 (cost data tampering), I-7 (cross-cost-center leak) | Transactional integrity, scoped API responses | Implemented |
| `pf-supply` | I-8 (API key leak), R-6 (unapproved reorder) | `Secret<>` types, approval workflow, audit trail | Implemented |
| `pf-enroll-portal` | S-4 (OIDC code intercept) | PKCE, state parameter CSRF protection, DoD banner (AC-8) | Implemented |
| `pf-admin-ui` | E-6 (cross-site access) | SiteId-scoped roles, RBAC enforcement | Implemented |

---

## 5. Residual Risks

The following risks are acknowledged and either accepted with compensating controls or require additional work.

### 5.1 Accepted Risks

| ID | Risk | Justification | Compensating Controls |
|----|------|---------------|----------------------|
| RR-1 | **Stolen CAC with known PIN grants full user access.** PrintForge cannot distinguish a legitimate CAC holder from someone who stole the card and knows the PIN. | This is inherent to all CAC/PIV-based systems. The DoD CAC issuance and loss-reporting process is the primary control. | PIN lockout after failed attempts (AC-7); all actions audited with EDIPI; physical security at printer panels; immediate revocation via OCSP on CAC loss report. |
| RR-2 | **DDIL mode operates on cached authentication data.** During extended WAN outages, cached OCSP responses may become stale, potentially allowing revoked certificates to authenticate. | DDIL mode is a deliberate availability trade-off. Printing must continue at installations during WAN outages. | Configurable auth cache TTL (default 4h); DDIL mode transitions audited; full re-validation on WAN restore; operations during DDIL limited to locally-submitted jobs only. |
| RR-3 | **Last-writer-wins conflict resolution during sync may lose edge modifications.** If the same job metadata is modified both centrally and locally during a network partition, the central version wins. | Central-wins is the safest default for a security-critical system. Edge modifications during DDIL are operational convenience, not the source of truth. | SYNC_CONFLICT audit events record both versions; vector clock history preserved for forensic review. |
| RR-4 | **SNMPv3 does not provide mutual authentication.** A compromised network segment could allow a rogue device to respond to SNMP queries, providing false telemetry data. | SNMPv3 AuthPriv provides message-level authentication and encryption. Full mutual authentication would require IPsec or 802.1X on the printer VLAN. | Discovery restricted to configured subnets; anomalous telemetry changes trigger alerts; printer identity verified via IPP Get-Printer-Attributes cross-reference. |

### 5.2 Risks Requiring Additional Controls

| ID | Risk | Required Action | Priority | Target Crate |
|----|------|----------------|----------|-------------|
| RR-5 | **No hardware security module (HSM) integration for JWT signing keys.** Currently, JWT signing keys are software-protected via `secrecy::Secret<String>`. An HSM or TPM would provide stronger key protection. | Evaluate integration with PKCS#11 / cloud HSM for JWT signing key storage. | Medium | `pf-auth` |
| RR-6 | **No intrusion detection at the application layer.** While the enclave provides network IDS/IPS, PrintForge does not have application-layer anomaly detection (e.g., detecting unusual print patterns, brute-force job submission). | Implement application-layer anomaly detection with configurable alert thresholds. | Medium | `pf-api-gateway`, `pf-job-queue` |
| RR-7 | **SCIM endpoint lacks IP allowlisting.** The SCIM endpoint authenticates callers via bearer token but does not restrict source IP addresses. A stolen SCIM token could be used from any network location within the enclave. | Add configurable IP allowlist for SCIM endpoint callers. | Low | `pf-user-provisioning` |
| RR-8 | **No dead-letter queue for failed audit writes.** If the audit database is unavailable, audit events may be lost. The current design logs an alert but does not buffer events. | Implement a local on-disk buffer for audit events when the database is unreachable, with replay on reconnect. | High | `pf-audit` |
| RR-9 | **Vendor API credentials are long-lived.** Supply chain vendor API keys do not rotate automatically. Key compromise would grant sustained access to vendor ordering systems. | Implement automated API key rotation with configurable intervals; alert on key age. | Low | `pf-supply` |
| RR-10 | **No Kubernetes admission control for PrintForge pod images.** While images are signed in the release pipeline, there is no admission webhook enforcing signature verification at deployment time. | Deploy a Sigstore/Cosign admission controller to verify OCI image signatures. | Medium | `deploy/helm/` |

---

## 6. Threat Model Maintenance

This threat model is a living document and must be updated when:

1. **New crates or components are added** to the PrintForge workspace.
2. **New trust boundaries are introduced** (e.g., new external integrations, new deployment topology).
3. **NIST control implementations change** in a way that affects mitigations listed here.
4. **Security incidents occur** that reveal previously unidentified threats.
5. **Residual risks (section 5.2) are addressed** -- move to the implemented mitigations table.

### Review Schedule

- **Quarterly:** Review residual risks and update priorities.
- **Per-release:** Validate that new features do not introduce unmitigated threats.
- **Annually:** Full threat model review with updated STRIDE analysis.

### Related Documents

- `docs/nist-800-53-mapping.md` -- NIST 800-53 Rev 5 control-to-code traceability matrix
- `docs/design-document.docx` -- PrintForge Design Document v1.0
- Root `CLAUDE.md` -- Architecture overview and coding standards
