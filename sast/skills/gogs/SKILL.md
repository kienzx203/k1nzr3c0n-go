# Gogs — @gogsghost cloud skill
> kind: ci-cd · severity: low · source: HackTricks-Cloud

## What it is
If an application passes an attacker-controlled **ref name** directly to a Git command **without `--` or `--end-of-options`**, a branch beginning with `--` can be parsed as a **Git option** instead of as data.<sup>[[1]](#references)</sup>

## Attack surface / review checklist
- enumerate identity, permissions, public exposure, secrets, logging

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/gogs-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
