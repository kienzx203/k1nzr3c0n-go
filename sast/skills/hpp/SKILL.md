# HTTP Parameter Pollution — @paramstorm skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
HTTP Parameter Pollution (HPP) is a web security vulnerability where an attacker injects multiple instances of the same HTTP parameter into a request. The server's behavior when processing duplicate parameters can vary, potentially leading to unexpected or exploitable behavior.

## Exploit payloads (from PayloadsAllTheThings)
- `/app?debug=false&debug=true`
- `/transfer?amount=1&amount=5000`
- `param=value1&param=value2`
- `param[]=value1`
- `param[]=value1&param[]=value2`
- `param[]=value1&param=value2`
- `param=value1&param[]=value2`
- `param=value1%26other=value2`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=HTTP%20Parameter%20Pollution
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [Parameter Pollution | JSON Injection](https://hacktricks.wiki/en/pentesting-web/parameter-pollution)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
