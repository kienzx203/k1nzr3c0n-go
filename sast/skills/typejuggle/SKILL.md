# Type Juggling — @loosecmp skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Loose Type comparisons occurs in many languages:

## Exploit payloads (from PayloadsAllTheThings)
- `<?php`
- `var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)`
- `var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));`
- `var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));`
- `var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));`
- `?>`
- `function validate_cookie($cookie,$key){`
- `$hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Type%20Juggling
- HackTricks Cloud: https://cloud.hacktricks.wiki/
