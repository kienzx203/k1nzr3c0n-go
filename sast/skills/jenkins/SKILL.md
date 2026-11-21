# Jenkins — @butler cloud skill
> kind: ci-cd · severity: high · source: HackTricks-Cloud

## What it is
Jenkins is a tool that offers a straightforward method for establishing a **continuous integration** or **continuous delivery** (CI/CD) environment for almost **any** combination of **programming languages** and source code repositories using pipelines. Furthermore, it automates various routine development tasks. While Jenkins doesn't eliminate the **need to create scripts for individual steps**, it does provide a fa

## Attack surface / review checklist
- basic jenkins information
- jenkins arbitrary file read to rce via remember me
- jenkins dumping secrets from groovy
- jenkins rce creating modifying pipeline
- jenkins rce creating modifying project
- jenkins rce with groovy script

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/jenkins-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
