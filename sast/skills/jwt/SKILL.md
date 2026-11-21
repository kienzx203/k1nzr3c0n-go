# JWT Attacks — @tokenbane skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
JSON Web Token : `Base64(Header).Base64(Data).Base64(Signature)`

## Exploit payloads (from PayloadsAllTheThings)
- `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # header`
- `eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # payload`
- `UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # signature`
- `{`
- `"typ": "JWT",`
- `"alg": "HS256"`
- `}`
- `{`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=JWT%20Attacks
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [JWT Vulnerabilities (JSON Web Tokens)](https://hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
