# GCP Security — @nimbus cloud skill
> kind: cloud · severity: high · source: HackTricks-Cloud

## What it is
Concepts such as **organization** hierarchy, **permissions** and other basic concepts are explained in:

## Attack surface / review checklist
- gcp basic information
- gcp cross project attacks
- gcp permissions for a pentest
- gcp persistence
- gcp post exploitation
- gcp privilege escalation
- gcp services
- gcp to workspace pivoting
- gcp unauthenticated enum and access
- permission risk categorizations

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
