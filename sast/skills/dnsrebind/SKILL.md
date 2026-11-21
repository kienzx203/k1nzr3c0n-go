# DNS Rebinding — @rebinder skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
This is often achieved by setting a very short TTL (time-to-live) for the initial DNS response, forcing the browser to re-resolve the domain.

## Exploit payloads (from PayloadsAllTheThings)
- `$ dig cname.example.com +noall +answer`
- `; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer`
- `;; global options: +cmd`
- `cname.example.com.            381     IN      CNAME   target.local.`
- `$ dig www.example.com +noall +answer`
- `; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer`
- `;; global options: +cmd`
- `localhost.example.com.            381     IN      CNAME   localhost.`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DNS%20Rebinding
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=DNS%20Rebinding
- HackTricks Cloud: https://cloud.hacktricks.wiki/
