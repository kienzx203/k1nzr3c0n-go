# Supabase — @baaswraith cloud skill
> kind: ci-cd · severity: medium · source: HackTricks-Cloud

## What it is
As per their **landing page**: Supabase is an open source Firebase alternative. Start your project with a Postgres database, Authentication, instant APIs, Edge Functions, Realtime subscriptions, Storage, and Vector embeddings.<sup>[[8]](#references)</sup>

## Attack surface / review checklist
- Supabase Security
- Basic Information
- Subdomain
- Database configuration
- API Configuration
- anon api keys
- secret / service_role api keys
- JWT Secret
- Authentication
- Signups
- RLS and Views: Write bypass via PostgREST
- OpenAPI-driven CRUD probing from anon/auth roles
- Passwords & sessions
- SMTP Settings
- Advanced Settings
- Storage
- Edge Functions
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
- HackTricks Cloud: https://cloud.hacktricks.wiki/en/pentesting-ci-cd/supabase-security/
- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud
