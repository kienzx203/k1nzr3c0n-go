---
name: secure-sdlc
description: Secure design review & SDLC assessment — ingest design/architecture docs, threat-model (STRIDE), derive security requirements (ASVS), find architecture risks, and give actionable secure-design recommendations across the SDLC phases. Load when assessing a project's design/SDLC rather than hunting runtime bugs.
metadata:
  type: appsec
  phase: design
---

# Secure design review & SDLC assessment

## INPUTS (read first)
Read the PROJECT DOCUMENTS (architecture, design specs, data-flow diagrams, API/Swagger, ERD,
infra/IaC, auth design, threat model if any). For PDF/DOCX extract text first. If code is present,
use it to check design-vs-implementation gaps. Build: components, trust boundaries, data stores,
external integrations, actors/roles, and the sensitive data each handles.

## THREAT MODEL (STRIDE per element / data-flow)
For each component and each data flow crossing a trust boundary, enumerate:
- **S**poofing — authentication of actors/services (mTLS, tokens, service identity).
- **T**ampering — integrity of data in transit/at rest (signing, TLS, validation).
- **R**epudiation — logging/audit, non-repudiation of sensitive actions.
- **I**nformation disclosure — confidentiality (encryption, least-exposure, PII handling).
- **D**enial of service — rate limits, quotas, resource bounds, backpressure.
- **E**levation of privilege — authz model, isolation, least privilege, trust boundaries.
Prioritise threats hitting crown jewels (auth, PII, money, admin, secrets).

## SECURITY REQUIREMENTS (map to OWASP ASVS)
Derive concrete requirements per area: authentication & session, access control, input/output
handling, cryptography & key management, secrets management, data protection & privacy, error/
logging, communications (TLS), config/hardening, dependency & supply-chain, and (if cloud) IAM/
network segmentation. State each as a verifiable requirement, not a platitude.

## ARCHITECTURE RISK ANALYSIS (common design anti-patterns)
Flag: missing/weak trust boundaries; client-side trust; shared secrets; no central authz; broken
multi-tenancy/isolation; sensitive data in logs/URLs/caches; unencrypted PII at rest; home-grown
crypto; implicit trust of internal services (SSRF/lateral); no input validation at boundaries;
monolithic blast radius; missing rate limiting; secrets in config/repos; no key rotation; overly
broad IAM; unsafe deserialization/formats; insecure defaults; no tenant data partitioning.

## SDLC PHASE GATES (assess maturity + gaps)
- Requirements: security/abuse cases, data classification, compliance (GDPR/PCI/HIPAA if relevant).
- Design: threat model exists & current, security design review gate.
- Implementation: secure-coding standards, SAST, secret-scanning, code review.
- Testing: DAST/SCA, security test cases, pen-test before release.
- Release/Ops: hardening, secrets mgmt, logging/monitoring/alerting, patch & dependency mgmt,
  incident response. Point out which gates are missing.

## DELIVERABLE
For each issue: the risk (threat + impact + affected asset), severity, the design recommendation
(concrete, implementable), and the ASVS/standard it satisfies. Separate CONFIRMED design flaws
from design QUESTIONS (where the docs are silent — ask). This is a DESIGN assessment: recommend
and threat-model; do not exploit.
