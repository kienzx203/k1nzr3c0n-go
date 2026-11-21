# Kubernetes Security — @helmsman cloud skill
> kind: cloud · severity: high · source: HackTricks-Cloud

## What it is
If you don't know anything about Kubernetes this is a **good start**. Read it to learn about the **architecture, components and basic actions** in Kubernetes:

## Attack surface / review checklist
- abusing roles clusterroles in kubernetes
- attacking kubernetes from inside a pod
- kubernetes api object operations
- kubernetes basic information
- kubernetes enumeration
- kubernetes enumeration
- kubernetes external secrets operator
- kubernetes hardening
- kubernetes helm template injection
- kubernetes kyverno
- kubernetes namespace escalation
- kubernetes network attacks
- kubernetes opa gatekeeper
- kubernetes pivoting to clouds
- kubernetes validatingwebhookconfiguration
- pentesting kubernetes services
- permission risk categorizations
- spiffe spire workload identity spoofing

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
