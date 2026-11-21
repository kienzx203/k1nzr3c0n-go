# SAST_k1nz — Agent Skills

One **skill per vulnerability agent**. Each `skills/<agent-id>/SKILL.md` is a focused
knowledge pack the agent uses when it reviews and (LLM-)verifies its own findings.

| agent id | codename | skill |
|---|---|---|
| sqli | @injektor | SQL / NoSQL Injection |
| cmdi | @shellghost | OS Command / Argument Injection |
| xss | @reflektor | Cross-Site Scripting |
| path | @traverser | Path Traversal / LFI / Upload |
| ssrf | @gateway | Server-Side Request Forgery |
| code | @evalisk | Code / Template / EL Injection |
| deserial | @unpickler | Insecure Deserialization |
| ldap | @dirwraith | LDAP Injection |
| xpath | @xcross | XPath / XQuery / XXE |
| redirect | @rerouter | Open Redirect / CRLF |
| injection | @wildcard | Generic / Log / Format / Trust-boundary |

## Skill format
Each `SKILL.md` has: **What it is · Code review (source→sink + sanitizers) · Exploit payloads ·
`## VERIFY` · Remediation · References**. The `## VERIFY` section (CONFIRMED / FALSE POSITIVE /
LIKELY rules) is extracted by `agent_c/agents.py` and injected as the per-finding `focus` for
that agent's LLM verify — so each agent judges with its own expert checklist.

## Knowledge sources
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks)
- [HackTricks Cloud](https://github.com/HackTricks-wiki/hacktricks-cloud)

Skills are editable: tweak a `SKILL.md` and the agent's verify guidance updates on the next scan
(no rebuild needed — the Python loader reads them at runtime).
