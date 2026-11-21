# Confidential Computing — @enclave cloud skill
> kind: cloud · severity: medium · source: HackTricks-Cloud

## What it is
Confidential Computing security review: identity, permissions, exposure and secrets.

## Attack surface / review checklist
- luks2 header malleability null cipher abuse

## VERIFY
- CONFIRMED when: the reviewed IaC / config / manifest / pipeline grants the risky
  exposure above — public access, wildcard principal/role, disabled auth or MFA, an
  over-broad scope/permission, a plaintext secret, or an unpinned/untrusted step — with
  no compensating control.
- FALSE POSITIVE when: least privilege is enforced, access is restricted/allow-listed,
  auth/MFA is on, secrets live in a vault/OIDC, steps are pinned, or the resource is
  intentionally and safely public.
- LIKELY when: the risky pattern is present but the surrounding guardrail (SCP, policy
  boundary, network rule, branch protection) is not visible in the reviewed files.

## References
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/confidential-computing/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
