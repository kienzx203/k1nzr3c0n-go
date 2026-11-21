# DigitalOcean — @dropletx cloud skill
> kind: cloud · severity: medium · source: HackTricks-Cloud

## What it is
Concepts such as hierarchy, access and other basic concepts are explained in:

## Attack surface / review checklist
- do basic information
- do permissions for a pentest
- do services

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/digital-ocean-pentesting/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
