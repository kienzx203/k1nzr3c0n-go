# Gitblit — @blitghost cloud skill
> kind: ci-cd · severity: low · source: HackTricks-Cloud

## What it is
Gitblit is a self‑hosted Git server written in Java.<sup>[[1]](#references)</sup> It can run as a standalone JAR or in servlet containers and ships an embedded SSH service (Apache MINA SSHD) for Git over SSH.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

## Attack surface / review checklist
- gitblit embedded ssh auth bypass cve 2024 28080

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/gitblit-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
