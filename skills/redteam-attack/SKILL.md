---
name: redteam-attack
description: Red-team adversary-emulation playbook — MITRE ATT&CK kill-chain, tradecraft, OPSEC, C2 discipline, and what to do when detected. Load when running an authorized red-team engagement so each step maps to ATT&CK, stays stealthy within ROE, and demonstrates the objective without damage or over-reach.
metadata:
  type: offensive
  phase: exploitation
  mitre: ATT&CK
---

# Red-team adversary-emulation playbook (authorized, within ROE)

## KILL CHAIN ↔ MITRE ATT&CK (map every action to a technique + weigh detection)
- **Recon (TA0043)**: passive first (OSINT, DNS, cert transparency, exposed services). Minimal
  active. Build the target + identities + trust map.
- **Resource/Initial Access (TA0001)**: valid accounts (T1078), exploit public-facing app (T1190),
  phishing only if ROE allows (T1566). One good low-noise vector beats spraying.
- **Execution (TA0002)**: prefer living-off-the-land (T1059 native shells, T1047 WMI) over dropping
  tooling. Situational awareness: whoami/privs, host, domain, reachable nets.
- **Persistence (TA0003)** — ONLY if ROE permits and ONLY to prove the objective; remove afterward.
- **Privilege Escalation (TA0004)**: local misconfig (T1068/T1548), token/cred abuse.
- **Credential Access (TA0006)**: LSASS/secrets (T1003) if authorized; do NOT crack/retain creds
  beyond engagement need. Prefer reuse over cracking.
- **Discovery (TA0007)** + **Lateral Movement (TA0008)**: map, then move via valid creds/remote
  services (T1021); pass-the-hash/ticket if authorized. Minimal hosts to reach the objective.
- **Collection/Impact — DEMONSTRATE ONLY**: read a canary / prove access to the crown jewel.
  NEVER exfiltrate real data, NEVER destroy/encrypt/DoS. The objective proof is the finish line.

## TRADECRAFT & OPSEC
- Detection-aware technique selection: if a quieter technique reaches the same goal, use it.
  Avoid known-signatured tooling/commands; obfuscate/rename where appropriate within ROE.
- Minimal footprint: targeted actions, not broad scans; staged/throttled; blend with normal hours.
- C2/beacon discipline (if used + authorized): long jitter/sleep, legit-looking domains/paths,
  minimal callbacks; don't leave live implants beyond the window.
- Clean up: remove files/accounts/implants you created; log what you did for the report.
- Validate concretely (id/whoami, read the canary) — capture exact commands + output as evidence.

## WHEN DETECTED / BLOCKED
- If blue team blocks a path or you're burned: stop that technique, note the detection (good for
  the report), and pivot to an alternate TTP — don't escalate noise or brute through. If scope/ROE
  is ambiguous or a step risks damage/out-of-scope, STOP and ask the operator.

## EVIDENCE & REPORTING
Record each outcome with the ATT&CK technique id, exact reproducible steps/commands, evidence,
the real business impact (what the access unlocks), detection notes, and remediation.

## HARD LIMITS (ROE IS ABSOLUTE)
In-scope + time-window + allowed-techniques only. No destruction, no real-data exfiltration, no
persistence/lateral beyond proving the objective, no DoS. Demonstrate — don't damage. Stop at proof.
