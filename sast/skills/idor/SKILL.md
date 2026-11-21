# IDOR / Broken Object Auth — @objwalker skill
> cats: IDOR, PARAM_TAMPERING, TRUST_BOUNDARY · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
IDOR stands for Insecure Direct Object Reference. It's a type of security vulnerability that arises when an application provides direct access to objects based on user-supplied input. As a result, attackers can bypass authorization and access resources in the system directly, potentially leading to unauthorized information disclosure, modification, or deletion.

## Exploit payloads (from PayloadsAllTheThings)
- `<?php`
- `$user_id = $_GET['user_id'];`
- `$user_info = get_user_info($user_id);`
- `...`
- `https://example.com/profile?user_id=124`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=IDOR%20/%20Broken%20Object%20Auth
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [IDOR (Insecure Direct Object Reference)](https://hacktricks.wiki/en/pentesting-web/idor)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
