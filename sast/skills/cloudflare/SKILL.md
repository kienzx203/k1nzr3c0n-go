# Cloudflare — @edgewraith cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
In a Cloudflare account there are some **general settings and services** that can be configured. In this page we are going to **analyze the security related settings of each section:**

## Attack surface / review checklist
- cloudflare domains
- cloudflare workers pass through proxy ip rotation
- cloudflare zero trust network

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/cloudflare-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
