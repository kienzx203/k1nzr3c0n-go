# IBM Cloud — @bluemix cloud skill
> kind: cloud · severity: medium · source: HackTricks-Cloud

## What it is
IBM Cloud combines platform as a service (PaaS) and infrastructure as a service (IaaS) and supports public, hybrid, multicloud, and Virtual Private Cloud (VPC) deployments. Its catalog includes compute, storage, networking, containers, application-development, security, database, data, and AI services.<sup>[[1]](#references)</sup>

## Attack surface / review checklist
- ibm basic information
- ibm hyper protect crypto services
- ibm hyper protect virtual server

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/ibm-cloud-pentesting/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
