# Cloud Env-Var Injection — @envleak cloud skill
> kind: cloud · severity: medium · source: HackTricks-Cloud

## What it is
Cloud workload APIs often let a caller set or override environment variables without changing source code or a container image. Job APIs may apply the values to only one execution, while service and function APIs usually persist them as configuration and restart or revise the workload. If the workload subsequently starts an interpreter that consumes security-sensitive startup variables, the override can preload attac

## Attack surface / review checklist
- Environment Variable Injection to Code Execution
- Interpreter Startup Variables
- Python PYTHONWARNINGS Version Note
- Cloud Services Exposing the Primitive
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-cloud/environment-variable-injection/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
