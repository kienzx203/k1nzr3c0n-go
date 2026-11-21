# Vercel — @edgeverc cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
In Vercel a **Team** is the complete **environment** that belongs a client and a **project** is an **application**.<sup>[[2]](#references)[[3]](#references)</sup>

## Attack surface / review checklist
- Vercel
- Basic Information
- Project Settings
- General
- Domains
- Environments
- Environment Variables
- Git
- Integrations
- Deployment Protection
- Functions
- Data Cache
- Cron Jobs
- Log Drains
- Security
- Advanced
- Project Firewall
- Firewall
- Custom Rules & IP Blocking
- Project Deployment
- Source
- Skew Protection
- Team Settings
- General

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/vercel-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
