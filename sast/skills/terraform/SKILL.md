# Terraform / IaC — @statewraith cloud skill
> kind: ci-cd · severity: high · source: HackTricks-Cloud

## What it is
HashiCorp Terraform is an **infrastructure as code tool** that lets you define both **cloud and on-prem resources** in human-readable configuration files that you can version, reuse, and share. You can then use a consistent workflow to provision and manage all of your infrastructure throughout its lifecycle. Terraform can manage low-level components like compute, storage, and networking resources, as well as high-lev

## Attack surface / review checklist
- Terraform Security
- Basic Information
- Terraform Lab
- RCE in Terraform: config file poisoning
- Terraform plan
- Malicious Terraform provider in a project
- Terraform Apply
- Secrets Dumps
- Abusing Terraform State Files
- RCE through provider state poisoning
- Deleting resources <a href="#deleting-resources" id="deleting-resources"></a>
- Replace blacklisted provider
- Terraform Cloud speculative plan RCE and credential exfiltration
- Compromising Terraform Cloud
- Using a token
- Escaping to the cloud
- Automatic Audit Tools
- [Snyk Infrastructure as Code (IaC)](https://snyk.io/product/infrastructure-as-code-security/)
- [Checkov](https://github.com/bridgecrewio/checkov) <a href="#install-checkov-from-pypi" id="install-checkov-from-pypi"></a>
- [terraform-compliance](https://github.com/terraform-compliance/cli)
- [tfsec](https://github.com/aquasecurity/tfsec)
- [terrascan](https://github.com/tenable/terrascan)
- [KICKS](https://github.com/Checkmarx/kics)
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/terraform-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
