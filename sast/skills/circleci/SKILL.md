# CircleCI — @orbit cloud skill
> kind: ci-cd · severity: high · source: HackTricks-Cloud

## What it is
In my testing I checked that as long as you have **write permissions over the repo in github**, you are going to be able to **manage its project settings in CircleCI** (set new ssh keys, get project api keys, create new branches with new CircleCI configs...).

## Attack surface / review checklist
- CircleCI Security
- Basic Information
- Permissions
- Env Variables & Secrets
- Attacks
- I filter by the repo branch where this config.yaml file is located: circleci-project-setup
- I filter by the repo branch where this config.yaml file is located: circleci-project-setup
- - image: cimg/base:stable
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/circleci-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
