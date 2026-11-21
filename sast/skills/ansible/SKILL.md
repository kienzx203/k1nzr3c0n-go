# Ansible Tower / AWX — @playghost cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
According to **this**, the main differences between Ansible Tower and AWX is the received support and the Ansible Tower has additional features such as role-based access control, support for custom APIs, and user-defined workflows.<sup>[[4]](#references)</sup>

## Attack surface / review checklist
- Ansible Tower / AWX / Automation controller Security
- Basic Information
- Differences
- Tech Stack
- Logical Components
- Job Execution Flow
- AWX lab creation for testing
- Build
- Run
- Or to create a more complex env
- Clean and build the UI
- Once migrations are completed and the UI is built, you can begin using AWX. The UI can be reached in your browser at https://localhost:8043/#/home, and the API can be found at https://localhost:8043/api/v2.
- Create an admin user
- Load demo data
- RBAC
- Supported roles
- Enumeration & Attack-Path Mapping with AnsibleHound
- Why is this useful?
- Prerequisites
- Building & Running
- Compile the collector
- Execute against the target instance
- BloodHound Transformation
- Defensive & Offensive Considerations

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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/ansible-tower-awx-automation-controller-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
