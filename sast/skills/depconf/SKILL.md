# Dependency Confusion — @pkgshadow skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Look for `npm`, `pip`, `gem` packages, the methodology is the same : you register a public package with the same name of private one used by the company and then you wait for it to be used.

## Exploit payloads (from PayloadsAllTheThings)
See the PayloadsAllTheThings folder linked below.

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Dependency%20Confusion
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Dependency%20Confusion
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [Dependency Confusion](https://hacktricks.wiki/en/pentesting-web/dependency-confusion)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
