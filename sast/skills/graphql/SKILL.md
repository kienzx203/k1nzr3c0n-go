# GraphQL Injection — @graphreaper skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
GraphQL endpoints are often exposed at predictable paths, most commonly:

## Exploit payloads (from PayloadsAllTheThings)
- `/v1/explorer`
- `/v1/graphiql`
- `/graph`
- `/graphql`
- `/graphql/console/`
- `/graphql.php`
- `/graphiql`
- `/graphiql.php`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=GraphQL%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/
