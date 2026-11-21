# CORS Misconfiguration — @originx skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Usually you want to target an API endpoint. Use the following payload to exploit a CORS misconfiguration on target `https://victim.example.com/endpoint`.

## Exploit payloads (from PayloadsAllTheThings)
- `GET /endpoint HTTP/1.1`
- `Host: victim.example.com`
- `Origin: https://evil.com`
- `Cookie: sessionid=...`
- `HTTP/1.1 200 OK`
- `Access-Control-Allow-Origin: https://evil.com`
- `Access-Control-Allow-Credentials: true`
- `{"[private API key]"}`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=CORS%20Misconfiguration
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [CORS - Misconfigurations & Bypass](https://hacktricks.wiki/en/pentesting-web/cors-bypass)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
