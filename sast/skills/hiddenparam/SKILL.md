# Hidden Parameters — @ghostparam skill
> cats: (advisory — no static taint rule yet) · severity: low
> sources: PayloadsAllTheThings, HackTricks

## What it is
x8 -u "https://example.com/" -w <wordlist>

## Exploit payloads (from PayloadsAllTheThings)
- `x8 -u "https://example.com/" -w <wordlist>`
- `x8 -u "https://example.com/" -X POST -w <wordlist>`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Hidden%20Parameters
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Hidden%20Parameters
- HackTricks Cloud: https://cloud.hacktricks.wiki/
