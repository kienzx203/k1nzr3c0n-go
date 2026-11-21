# Chef Automate — @cookbook cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
Chef Automate is a platform for infrastructure automation, compliance, and application delivery.<sup>[[1]](#references)</sup> It exposes a web UI (often Angular) that talks to backend gRPC services via a gRPC-Gateway, providing REST-like endpoints under paths such as /api/v0/.<sup>[[3]](#references)</sup>

## Attack surface / review checklist
- chef automate enumeration and attacks

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/chef-automate-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
