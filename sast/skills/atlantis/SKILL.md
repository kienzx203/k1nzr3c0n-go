# Atlantis — @planwraith cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
Atlantis is a pull-request-driven service that runs Terraform commands from comments on a Git host.<sup>[[1]](#references)[[13]](#references)</sup>

## Attack surface / review checklist
- Atlantis Security
- Basic Information
- Local Lab
- Atlantis Access
- Server Configuration
- Atlantis Commands
- Get help
- Run terraform plan
- -d directory
- -p project
- --verbose
- You can also add extra terraform options
- Run terraform apply
- -d directory
- -p project
- -w workspace
- --auto-merge-disabled
- --verbose
- You can also add extra terraform options
- Attacks
- Post-Exploitation
- Mitigations
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/atlantis-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
