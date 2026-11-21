# CSV / Formula Injection — @formulax skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
CSV Injection, also known as Formula Injection, is a security vulnerability that occurs when untrusted input is included in a CSV file. Any formula can be started with:

## Exploit payloads (from PayloadsAllTheThings)
- `=`
- `+`
- `–`
- `@`
- `DDE ("cmd";"/C calc";"!A0")A0`
- `@SUM(1+1)*cmd|' /C calc'!A0`
- `=2+5+cmd|' /C calc'!A0`
- `=cmd|' /C calc'!'A1'`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=CSV%20/%20Formula%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/
