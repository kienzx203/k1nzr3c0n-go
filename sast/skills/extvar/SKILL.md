# External Variable Modification — @varshift skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
The `extract()` function in PHP imports variables from an array into the current symbol table. While it may seem convenient, it can introduce serious security risks, especially when handling user-supplied data.

## Exploit payloads (from PayloadsAllTheThings)
- `<?php`
- `$authenticated = false;`
- `extract($_GET);`
- `if ($authenticated) {`
- `echo "Access granted!";`
- `} else {`
- `echo "Access denied!";`
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
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/External%20Variable%20Modification
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=External%20Variable%20Modification
- HackTricks Cloud: https://cloud.hacktricks.wiki/
