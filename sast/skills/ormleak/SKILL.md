# ORM Leak — @ormseep skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
The following code is a basic example of an ORM querying the database.

## Exploit payloads (from PayloadsAllTheThings)
- `users = User.objects.filter(**request.data)`
- `serializer = UserSerializer(users, many=True)`
- `{`
- `"username": "admin",`
- `"password__startswith": "p"`
- `}`
- `{`
- `"created_by__user__password__contains": "p"`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/ORM%20Leak
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=ORM%20Leak
- HackTricks Cloud: https://cloud.hacktricks.wiki/
