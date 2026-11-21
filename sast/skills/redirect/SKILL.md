# Open Redirect / CRLF / HTTP Response Splitting — @rerouter skill
> cats: OPEN_REDIRECT, CRLF, HTTP_SPLITTING · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input sets a redirect target (phishing/OAuth token theft) or is injected into HTTP
headers with CR/LF (response splitting, header injection, cache poisoning).

## Code review — source → sink
- REDIRECT SINKS: `sendRedirect(user)`, `response.Redirect`, Flask `redirect(user)`,
  `res.redirect`, `header("Location: "+user)`, OAuth `redirect_uri`/`return_to`/`next` params.
- CRLF SINKS: `setHeader`/`addHeader` with user data, `header()` (PHP), cookie values,
  logging into headers.
- SANITIZERS (SAFE): allow-list of redirect targets / relative-path-only check, strip/reject
  `\r\n`, framework header APIs that reject control chars.

## Exploit payloads
Open redirect `//evil.com` · `https://evil.com` · `/\evil.com` · `https:evil.com` ·
`http://trusted.com@evil.com` · CRLF `%0d%0aSet-Cookie:x=y` · `%0d%0aLocation:...` · header inject.

## VERIFY
- CONFIRMED when: tainted data sets a redirect `Location`/`redirect_uri` with **no allow-list /
  no host check**, or reaches a header/cookie write **without CR/LF stripping**.
- FALSE POSITIVE when: redirect target is allow-listed or forced relative (host stripped), or the
  header API rejects control chars, or newlines are stripped/encoded.
- LIKELY when: only partial validation (e.g. `startsWith('/')` bypassable by `//` or `/\`) or the
  check isn't visible.

## Remediation
Allow-list redirect destinations; force same-site/relative; validate OAuth `redirect_uri` exact
match; strip/reject CR/LF in all header values.

## References
- PayloadsAllTheThings/Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- CRLF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html

## HackTricks pages (1)

- [Open Redirect](https://hacktricks.wiki/en/pentesting-web/open-redirect)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
