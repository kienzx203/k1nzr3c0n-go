---
name: bugbounty-methodology
description: Bug-bounty hunting playbook — recon → attack surface → per-class testing → chaining → impact. Load when hunting a web/API target so you test the right classes the right way, report triager-grade findings, and DON'T submit noise. Covers the full OWASP + logic-bug set, access-control (2-account) testing, and what NOT to report.
metadata:
  type: offensive
  phase: exploitation
---

# Bug-bounty hunting playbook

## RECON → ATTACK SURFACE (do first, cheap, high leverage)
- Subdomains, live hosts, tech stack + versions, WAF/CDN. Virtual hosts.
- Endpoints/routes, parameters (incl. hidden/undocumented), API shapes (REST/GraphQL/gRPC),
  auth flows, file uploads, admin/debug/actuator/swagger, JS files → extract endpoints + secrets.
- Map roles/privilege levels and object-ownership (you need ≥2 accounts to test access control).
- Prioritise toward crown jewels: auth, PII, money/transactions, admin, secrets.

## PER-CLASS TESTING (test every plausible class per input — not just the obvious one)
- **Access control (highest ROI)**: IDOR/BOLA — swap IDs/UUIDs across TWO accounts; missing
  function-level authz (call admin endpoints as low-priv); forced browsing; mass assignment /
  over-posting (add `role`, `is_admin`, `price` fields); horizontal + vertical privilege.
- **Injection**: SQL/NoSQL (error + boolean + time based), OS-command, LDAP/XPath, template
  (SSTI — `${7*7}`/`{{7*7}}` per engine), code/eval, header/CRLF, ORM-raw.
- **XSS**: reflected, stored (persists for other users = high), DOM (sinks: innerHTML, eval,
  location, document.write). Prove with a benign `alert(document.domain)` or a canary callback.
- **SSRF**: any server-fetched URL/host/webhook/import/PDF/avatar — try internal IPs, cloud
  metadata (169.254.169.254), DNS-rebind; blind SSRF → out-of-band callback.
- **Auth/session**: JWT (alg=none, weak secret, kid/jku), fixation, missing expiry, password
  reset token leakage/predictability, OAuth redirect_uri, 2FA bypass, response-manipulation.
- **Business logic**: price/quantity/negative-value tampering, coupon/replay, workflow/step
  skipping, race conditions (parallel requests → double-spend), insecure direct state change.
- **File**: path traversal, LFI/RFI, arbitrary upload (extension/content-type bypass, path),
  zip-slip, XXE (external entity, blind OOB).
- **Other**: open redirect, CORS (reflected origin + credentials), CSRF (state-change,
  cookie-auth, no token), SSTI, prototype pollution, GraphQL (introspection, batching, nested
  DoS, field authz), known-vulnerable component versions (verify the vulnerable path is used).

## CHAINING (this is where real impact / top bounties come from)
- Open redirect + OAuth/token → account takeover.
- Self-XSS + login-CSRF / cookie-set → stored-XSS impact.
- IDOR (read) + mass-assignment (write) → full account/object takeover.
- SSRF + cloud metadata → credential theft → infra access.
- Low-priv API + missing authz → admin actions. Always escalate a "low" into its true impact.

## CONFIRM & IMPACT
- Reproduce reliably; understand WHY (no validation/authz on the path). A WAF reflection or a
  stack trace is a lead, not a bug. Rate severity by REAL impact to users/data/money, CVSS v3.1.

## DO NOT REPORT (triagers reject these → protect signal/reputation)
- Self-XSS with no chain; missing security headers / cookie flags with no demonstrated impact;
  best-practice/"informational" (SPF/DMARC, version disclosure, directory listing of public files);
  CVE-version match without a working PoC on this target; clickjacking on non-sensitive pages;
  rate-limiting absence alone; theoretical CSRF on non-state-changing or token-protected actions;
  anything out of scope or already known/resolved by the program. If impact can't be shown, don't submit.

## RULES
Strictly in scope; honor rate limits + forbidden tests; use test accounts; never exfiltrate real
user data, never DoS, never pivot out of scope. Demonstrate impact, then STOP.
