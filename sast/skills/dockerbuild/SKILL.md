# Docker Build Context — @contextx cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
If a CI/CD platform or hosted builder lets contributors specify the Docker build context path and Dockerfile path, you can often set the context to a parent directory (e.g., "..") and make host files part of the build context. Then, an attacker-controlled Dockerfile can COPY and exfiltrate secrets found in the builder user’s home (for example, ~/.docker/config.json). Stolen registry tokens may also work against the p

## Attack surface / review checklist
- Abusing Docker Build Context in Hosted Builders (Path Traversal, Exfil, and Cloud Pivot)
- TL;DR
- Attack surface
- PoC: Path traversal via Docker build context
- PoC: Dockerfile to ingest and exfiltrate the host context
- Cloud pivot with overprivileged tokens (example: Fly.io Machines API)
- Secret theft from compromised hosted services
- Install tcpdump inside the machine
- Capture traffic
- References

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/docker-build-context-abuse/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
