# Exposed .git / SCM — @repoleak skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Exposing the version control system folders on a web server can lead to severe security risks, including:

## Exploit payloads (from PayloadsAllTheThings)
- `location /.git {`
- `deny all;`
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
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Source%20Code%20Management
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Exposed%20.git%20/%20SCM
- HackTricks Cloud: https://cloud.hacktricks.wiki/
