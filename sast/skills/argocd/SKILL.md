# ArgoCD — @gitops cloud skill
> kind: ci-cd · severity: high · source: HackTricks-Cloud

## What it is
From an attacker perspective, treat Argo CD as a **deployment engine with Kubernetes credentials**. A useful Argo CD compromise can lead to:

## Attack surface / review checklist
- Argo CD Security
- Basic Information
- Architecture & Interesting Components
- Public API / UI Attacks
- Trusted Git Repository Abuse
- Direct argocd-repo-server Abuse
- Unauthenticated Repo-Server RCE via Kustomize Options
- Redis Cache Poisoning to Deploy Manifests
- ApplicationSet Attacks
- Post-Exploitation
- Detection & Hardening
- Static Analysis Note: Typed API Requests in CodeQL
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/argocd-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
