# Serverless Framework — @lambdax cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
An **Organization** is the highest-level entity within the Serverless Framework ecosystem. It represents a **collective group**, such as a company, department, or any large entity, that encompasses multiple projects, teams, and applications.<sup>[[1]](#references)</sup>

## Attack surface / review checklist
- Serverless.com Security
- Basic Information
- Organization
- Team
- Application
- Services
- Tutorial
- Create temp folder for the tutorial
- Install Serverless cli
- Generate template
- Indicate a name like "Tutorial"
- Login/Register
- Create A New App
- Indicate a name like "tutorialapp)
- "org" ensures this Service is used with the correct Serverless Framework Access Key.
- "app" enables Serverless Framework Dashboard features and sharing them with other Services.
- "service" is the name of this project. This will also be added to your AWS resource names.
- "org" ensures this Service is used with the correct Serverless Framework Access Key.
- "app" enables Serverless Framework Dashboard features and sharing them with other Services.
- "service" is the name of this project. This will also be added to your AWS resource names.
- Security Review of Serverless.com
- Misconfigured IAM Roles and Permissions
- Insecure Secrets and Configuration Management
- Vulnerable Code and Dependencies

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/serverless.com-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
