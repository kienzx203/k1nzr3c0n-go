# Azure Security — @skyforge cloud skill
> kind: cloud · severity: high · source: HackTricks-Cloud

## What it is
Learn the basics of Azure and Entra ID in the following page:

## Attack surface / review checklist
- az basic information
- az cross tenant and cross subscription attacks
- az device registration
- az enumeration tools
- az lateral movement cloud on prem
- az permissions for a pentest
- az persistence
- az post exploitation
- az privilege escalation
- az services
- az unauthenticated enum and initial entry
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
