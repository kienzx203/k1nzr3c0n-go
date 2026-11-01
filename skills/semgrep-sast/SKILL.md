---
name: semgrep-sast
description: Use when you have source code or code snippets from a target and want fast white-box bug hunting / code review with Semgrep — detecting common bug classes (SQLi, XSS, command injection, path traversal, SSRF, deserialization, hardcoded secrets) and writing or refining CUSTOM detection rules, including IaC (Terraform, Kubernetes, Docker, CloudFormation). Modeled on the Semgrep skills.
metadata:
  type: offensive
  phase: vulnerability-analysis
  tools: semgrep, semgrep-rules, SARIF
---

# Semgrep — white-box static analysis & custom rules

Semgrep is the fast path when you have CODE (a repo, a leaked file, a JS bundle, an
IaC tree). Pattern + lightweight dataflow/taint, so it scales to a whole codebase
in seconds and you can author rules on the fly for THIS target's footguns.

## 1. Run the baseline
- `semgrep --config auto` (community rules) or `--config p/<ruleset>` (e.g.
  `p/owasp-top-ten`, `p/javascript`, `p/python`, `p/secrets`). Add `--sarif
  -o out.sarif` for structured, diffable results (feeds appsec-code-audit).
- Scope to changed/interesting paths; exclude vendored/test dirs to cut noise.

## 2. Bug classes Semgrep is strong at
- **Injection**: SQLi (string-built queries), **command injection** (exec/spawn
  with tainted args), **path traversal** (user input → fs path), **SSRF** (user
  input → outbound request), **XSS** (unescaped sink in template/DOM),
  **deserialization** (pickle/yaml.load/ObjectInputStream), **SSTI**, LDAP/XPath.
- **Secrets / crypto**: hardcoded keys/tokens, weak hashing, ECB, static IVs.
- **AuthZ**: missing decorator/guard on a route (framework-specific pattern).

## 3. Writing & refining CUSTOM rules (the real value)
Generic rules miss target-specific sinks. For a bug class you care about:
```yaml
rules:
  - id: tainted-exec
    languages: [python]
    message: user input reaches os.system
    severity: ERROR
    mode: taint
    pattern-sources: [{ pattern: "request.$X" }]
    pattern-sinks:   [{ pattern: "os.system(...)" }]
```
- Use `mode: taint` with `pattern-sources`/`pattern-sinks`/`pattern-sanitizers`
  for dataflow, not just a single `pattern`.
- Refine against FALSE POSITIVES: add sanitizers you observe; `pattern-not` to
  exclude safe shapes. Iterate `semgrep --test` with `.fixtest` cases.
- After confirming ONE bug, turn its root pattern into a rule and sweep for every
  variant (see appsec-code-audit variant analysis).

## 4. Infrastructure-as-Code
`semgrep --config p/terraform | p/kubernetes | p/dockerfile`: public S3/buckets,
`0.0.0.0/0` ingress, privileged containers, hostPath mounts, missing
`readOnlyRootFilesystem`, secrets in env. Cross-ref cloud-security /
container-k8s-escape to turn a misconfig into real impact.

## Discipline
A Semgrep finding is a LEAD. Confirm reachability + a live PoC before
`[CONFIRMED]` (finding-discipline) — a matched pattern in dead/unreachable code is
INFO. Scanning code is read-only; keep any exploitation non-destructive and
in-scope.
