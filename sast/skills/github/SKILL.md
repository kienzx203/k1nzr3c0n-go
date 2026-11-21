# GitHub Actions — @actionsx cloud skill
> kind: ci-cd · severity: high · source: HackTricks-Cloud

## What it is
(From here) At a high level, **GitHub is a website and cloud-based service that helps developers store and manage their code, as well as track and control changes to their code**.<sup>[[8]](#references)</sup>

## Attack surface / review checklist
- abusing github actions
- accessible deleted data in github
- basic github information

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/github-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
