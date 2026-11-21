# ReDoS (Regex DoS) — @catastro skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
These regular expressions can be exploited with `aaaaaaaaaaaaaaaaaaaaaaaa!` (20 'a's followed by a '!').

## Exploit payloads (from PayloadsAllTheThings)
- `aaaaaaaaaaaaaaaaaaaa!`
- `$pattern = '/(a+)+$/';`
- `$subject = str_repeat('a', 1000) . 'b';`
- `if (preg_match($pattern, $subject)) {`
- `echo "Match found";`
- `} else {`
- `echo "No match";`
- `}`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Regular%20Expression
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=ReDoS%20%28Regex%20DoS%29
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [Regular Expression Denial of Service - ReDoS](https://hacktricks.wiki/en/pentesting-web/regular-expression-denial-of-service-redos)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
