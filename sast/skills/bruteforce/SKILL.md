# Missing Rate Limiting — @ratebreak skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
In a web context, brute-forcing refers to the method of attempting to gain unauthorized access to web applications, particularly through login forms or other user input fields. Attackers systematically input numerous combinations of credentials or other values (e.g., iterating through numeric ranges) to exploit weak passwords or inadequate security measures.

## Exploit payloads (from PayloadsAllTheThings)
- `Username: password`
- `Username1:Password1`
- `Username1:Password2`
- `Username1:Password3`
- `Username1:Password4`
- `Username1:Username1`
- `Username2:Username2`
- `Username3:Username3`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Brute%20Force%20Rate%20Limit
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Missing%20Rate%20Limiting
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (2)

- [Captcha Bypass](https://hacktricks.wiki/en/pentesting-web/captcha-bypass)
- [Rate Limit Bypass](https://hacktricks.wiki/en/pentesting-web/rate-limit-bypass)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
