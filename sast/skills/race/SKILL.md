# Race Condition / TOCTOU — @ghostrace skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Limit-overrun refers to a scenario where multiple threads or processes compete to update or access a shared resource, resulting in the resource exceeding its intended limits.

## Exploit payloads (from PayloadsAllTheThings)
- `engine.queue(request, gate='race1')`
- `engine.queue(request, gate='race1')`
- `engine.openGate('race1')`
- `def queueRequests(target, wordlists):`
- `engine = RequestEngine(endpoint=target.endpoint,`
- `concurrentConnections=30,`
- `requestsPerConnection=30,`
- `pipeline=False`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Race%20Condition%20/%20TOCTOU
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [Race Condition](https://hacktricks.wiki/en/pentesting-web/race-condition)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
