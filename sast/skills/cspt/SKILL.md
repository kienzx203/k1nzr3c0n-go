# Client-Side Path Traversal — @clientrav skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
A post-serving page calls the fetch function, sending a request to a URL with attacker-controlled input which is not properly encoded in its path, allowing the attacker to inject `../` sequences to the path and make the request get sent to an arbitrary endpoint. This behavior is referred to as a CSPT vulnerability.

## Exploit payloads (from PayloadsAllTheThings)
See the PayloadsAllTheThings folder linked below.

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Path%20Traversal
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Client-Side%20Path%20Traversal
- HackTricks Cloud: https://cloud.hacktricks.wiki/
