# Concourse CI — @pipewraith cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
Concourse allows you to **build pipelines** to automatically run tests, actions and build images whenever you need it (time based, when something happens...)<sup>[[1]](#references)[[2]](#references)</sup>

## Attack surface / review checklist
- concourse architecture
- concourse enumeration and attacks
- concourse lab creation

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/concourse-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
