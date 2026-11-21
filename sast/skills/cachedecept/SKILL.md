# Web Cache Deception/Poisoning — @cachewraith skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Example of Web Cache Deception:

## Exploit payloads (from PayloadsAllTheThings)
- `Values: User-Agent`
- `Values: Cookie`
- `Header: X-Forwarded-Host`
- `Header: X-Host`
- `Header: X-Forwarded-Server`
- `Header: X-Forwarded-Scheme (header; also in combination with X-Forwarded-Host)`
- `Header: X-Original-URL (Symfony)`
- `Header: X-Rewrite-URL (Symfony)`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Web%20Cache%20Deception/Poisoning
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (3)

- [Cache Poisoning and Cache Deception](https://hacktricks.wiki/en/pentesting-web/cache-deception/README)
- [Cache Poisoning to DoS](https://hacktricks.wiki/en/pentesting-web/cache-deception/cache-poisoning-to-dos)
- [Cache Poisoning via URL discrepancies](https://hacktricks.wiki/en/pentesting-web/cache-deception/cache-poisoning-via-url-discrepancies)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
