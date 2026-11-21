---
name: secure-sdlc
description: Secure design review & SDLC assessment — ingest design/architecture/API/IaC docs, threat-model (STRIDE + LINDDUN privacy + attack trees), derive security requirements (OWASP ASVS + API Top 10), analyse architecture & cloud/supply-chain risk, assess SDLC maturity (SAMM/BSIMM/SSDF) and give prioritized, actionable secure-design recommendations. Load when assessing a project's design/SDLC rather than hunting runtime bugs.
metadata:
  type: appsec
  phase: design
---

# Secure design review & SDLC assessment (expert)

## 0. INPUTS & SYSTEM MODEL (do first)
Read the PROJECT DOCUMENTS (architecture, HLD/LLD, data-flow diagrams, sequence diagrams, API
specs/Swagger/AsyncAPI, ERD/schema, infra/IaC — Terraform/k8s/Helm, auth/IAM design, existing
threat model, compliance scope). PDF/DOCX → extract text (pdftotext/unzip). If code exists, use it
to check design-vs-implementation drift.
Build the model: **components/services, trust boundaries, data flows (esp. boundary-crossing),
data stores, external/third-party integrations, actors & roles, and the data classification
each element handles** (public / internal / confidential / regulated-PII/PHI/PCI). A DFD with
trust boundaries is the backbone of the whole review.

## 1. THREAT MODELING
### STRIDE (per element & per boundary-crossing data flow)
- **Spoofing** → authn of users AND service-to-service (mTLS, signed tokens, workload identity);
  no shared/ambient trust.
- **Tampering** → integrity in transit (TLS) & at rest (signing, checksums), input validation at
  every boundary, message/queue integrity.
- **Repudiation** → tamper-evident audit logging of security-relevant actions, correlation IDs.
- **Information disclosure** → confidentiality (encryption, field-level for PII), least exposure,
  no secrets/PII in logs/URLs/caches/error messages, proper data retention/deletion.
- **Denial of service** → rate limits, quotas, timeouts, circuit breakers, resource bounds,
  pagination, backpressure, cost controls (cloud).
- **Elevation of privilege** → central authorization, least privilege, strong tenant isolation,
  no trust of client-supplied authz, defense-in-depth.
### LINDDUN (privacy threats — do when PII/PHI is in scope)
Linkability, Identifiability, Non-repudiation (privacy sense), Detectability, Disclosure,
Unawareness, Non-compliance → data minimization, purpose limitation, consent, anonymization/
pseudonymization, retention/erasure (GDPR/CCPA), DPIA triggers.
### Attack trees for crown jewels
For each crown jewel (auth, money, admin, PII, secrets) sketch the attacker paths and verify a
control cuts each path. Prioritise by impact × feasibility.

## 2. SECURITY REQUIREMENTS → OWASP ASVS (state each as verifiable)
Map gaps to ASVS chapters: V1 Architecture, V2 Authentication, V3 Session, V4 Access Control,
V5 Validation/Encoding/Injection, V6 Cryptography, V7 Error/Logging, V8 Data Protection,
V9 Communications, V10 Malicious Code, V11 Business Logic, V12 Files/Resources, V13 API/Web
Service, V14 Config. Pick the target level (1/2/3) from data sensitivity.
### API-specific — OWASP API Security Top 10
BOLA/object-level authz, broken authentication, broken object-property-level authz (mass
assignment / excessive data exposure), unrestricted resource consumption, broken function-level
authz, unrestricted access to sensitive business flows, SSRF, security misconfiguration, improper
inventory (shadow/zombie APIs), unsafe third-party API consumption.

## 3. ARCHITECTURE & PLATFORM RISK (design anti-patterns to flag)
- Missing/weak trust boundaries; client-side trust (authz/price/validation in client); no central
  policy/authz service; broken multi-tenancy & data partitioning; implicit trust of internal
  services (→ SSRF/lateral); home-grown crypto; secrets in config/repo/env/images; no key rotation
  or KMS/HSM; PII at rest unencrypted or in logs/URLs; unsafe deserialization/formats; insecure
  defaults; monolithic blast radius; no input validation at boundaries; synchronous trust of
  webhooks/callbacks.
- **Cloud/IaC**: over-broad IAM (wildcards), public buckets/DBs, no network segmentation/SG least
  privilege, unencrypted volumes, no logging (CloudTrail), exposed metadata (IMDSv1→SSRF), secrets
  in user-data, no least-privilege service accounts, missing WAF, container running as root,
  no image scanning/signing, k8s RBAC too broad, no network policies, privileged pods.
- **Supply chain (SSDF / SLSA)**: dependency provenance & pinning, SCA in CI, SBOM, signed
  artifacts/images, locked build, protected branches, review gates, CI secrets hygiene, dependency
  confusion risk.

## 4. SDLC MATURITY & PHASE GATES (assess maturity, cite SAMM/BSIMM/NIST SSDF)
- Requirements: security & abuse/misuse cases, data classification, compliance mapping.
- Design: threat model exists & kept current, security design-review gate.
- Implementation: secure-coding standards, SAST, secret scanning, mandatory code review.
- Verification: DAST, SCA, security test cases, pen-test before release, IaC scanning.
- Release/Operate: hardening baselines, secrets management, centralized logging/monitoring/
  alerting, patch & dependency management, WAF/RASP, incident response & runbooks, vuln disclosure.
Rate each gate present / partial / missing and recommend the next maturity step.

## 5. DELIVERABLE (per issue)
Risk statement (STRIDE/LINDDUN threat + impact + affected asset + attacker path), severity
(business impact), the concrete, implementable DESIGN recommendation, and the ASVS/API-Top10/
standard it satisfies. Separate CONFIRMED design flaws from DESIGN QUESTIONS (docs silent → ask
the human). End with a prioritized roadmap (quick wins → structural changes) + an SDLC maturity
summary. This is a DESIGN assessment — threat-model and recommend; never exploit.
