---
name: recon-to-attack
description: Use after recon lands to turn the attack surface into exploitation — the router that maps what recon_graph/recon_findings show (web, AD/network, cloud, secrets, takeover, shell, mobile, CI/CD, container, AI) to the exact offensive skill to invoke next. The bridge between the k1nzr3c0n recon engine and the offensive skill library.
metadata:
  type: process
---

# Recon → Attack Router (surface ⇒ which skill to invoke)

You have a recon engine (`recon-engine` / `workflow-control`) AND a library of offensive
domain skills. This is the connective tissue: **read the surface, then INVOKE the matching
skill** instead of attacking from memory. Each skill carries the real tradecraft + its
`references/` library.

## Always load first (discipline — the guardrails)
Invoke these up front and keep them in force for the whole engagement:
- `scope-discipline` — no target without authorization (names AND dedicated origin IPs).
- `opsec-discipline` — detection awareness, throttling, cleanup, redaction.
- `finding-discipline` — no confirmed finding without reproducible proof.
- `threat-model-discipline` — model the surface, track tested/untested drift.
(For sequencing the whole kill chain with gates, `engagement-flow`.)

## Route by what the surface shows
Read it cheaply first: `recon_graph(target, summary=true)` for the shape, then
`recon_graph(target, q=…)` / `recon_findings` / `recon_assets` to confirm. Then invoke:

| Recon signal (recon_graph / findings) | Invoke skill |
|---|---|
| Live HTTP hosts, URLs, params, JS, APIs (fam subdomain/url/param; status 2xx/401/403) | `web-pentest` + `vulnerability-analysis` |
| Dangling CNAME / takeover finding (provider + no origin; `sev:` takeover) | `web-pentest` (subdomain-takeover section) |
| Non-web service ports — SMB/LDAP/Kerberos/RDP/WinRM/MSSQL (`svc:smb/ldap/rdp/winrm/mssql`) | `network-attack` + `active-directory-attack` |
| DB / cache / search ports — mysql/postgres/redis/mongodb/elastic (`svc:` or `port:risky`) | `network-attack` |
| Cloud buckets / metadata / CDN-origin / cloud IP ranges (bucket, cdn, intel nodes) | `cloud-security` |
| Container / k8s ports — docker 2375/6 · kube 6443/10250/2379 (`svc:docker/k8s`) | `container-k8s-escape` |
| Secrets / keys / tokens in JS/config/breach (secret nodes, `secret:aws/jwt/github…`) | `red-team-ops` (cred handling) + reuse across every auth surface |
| An obtained shell / foothold (Linux) | `privesc-linux` → then `edr-evasion` if monitored |
| An obtained shell / foothold (Windows) | `privesc-windows` + `active-directory-attack` → `edr-evasion` |
| Need an initial-access vector (phishing/exposed panel/default creds) | `initial-access` |
| Mobile app (APK/IPA) in scope | `mobile-pentest` |
| CI/CD, pipeline, or package/supply-chain surface | `cicd-supply-chain` |
| AI/LLM/MCP/agent endpoints | `ai-agent-redteam` |
| Exotic: wireless/RF, crypto, reverse-eng, browser, macOS | the matching domain skill (list the library first) |

Not sure which exists? List the skill library (the Skill tool shows every skill +
description) and pick by description — don't guess a name.

## The loop position
1. Recon lands (`workflow-control` → `recon-engine`).
2. **Route here**: summary the surface → invoke the matching domain skill(s).
3. Attack per that skill's tradecraft; validate with a minimal non-destructive PoC
   (`finding-discipline`); persist (`report_finding` / `insert_assets` / `record_fact`).
4. New surface discovered mid-attack → narrow loop back to `recon-engine` for it, then
   re-route here.

## Boundaries
Stay inside `scope-discipline` at every step; keep scope-sensitive pivots OFF unless
authorized; prove impact without bulk exfil. The skills are tradecraft references — you
still run the actual tools (bash/http/probe) in-scope and record real evidence.
