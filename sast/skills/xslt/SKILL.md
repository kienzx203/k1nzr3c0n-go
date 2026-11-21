# XSLT Injection — @stylebend skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
No known tools currently exist to assist with XSLT exploitation.

## Exploit payloads (from PayloadsAllTheThings)
- `<?xml version="1.0" encoding="utf-8"?>`
- `<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">`
- `<xsl:template match="/fruits">`
- `<xsl:value-of select="system-property('xsl:vendor')"/>`
- `</xsl:template>`
- `</xsl:stylesheet>`
- `<?xml version="1.0" encoding="UTF-8"?>`
- `<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/x`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=XSLT%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [XSLT Server-Side Injection (Extensible Stylesheet Language Transformations)](https://hacktricks.wiki/en/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
