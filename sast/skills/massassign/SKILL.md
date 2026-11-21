# Mass Assignment — @bulkbind skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Mass assignment vulnerabilities are most common in web applications that use Object-Relational Mapping (ORM) techniques or functions to map user input to object properties, where properties can be updated all at once instead of individually. Many popular web development frameworks such as Ruby on Rails, Django, and Laravel (PHP) offer this functionality.

## Exploit payloads (from PayloadsAllTheThings)
- `{`
- `"username": "attacker",`
- `"email": "attacker@email.com",`
- `"password": "unsafe_password",`
- `"isAdmin": true`
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
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mass%20Assignment
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Mass%20Assignment
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [Mass Assignment (CWE-915) – Privilege Escalation via Unsafe Model Binding](https://hacktricks.wiki/en/pentesting-web/mass-assignment-cwe-915)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
