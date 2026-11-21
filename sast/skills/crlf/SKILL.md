# CRLF / HTTP Splitting / Log — @newliner skill
> cats: CRLF, HTTP_SPLITTING, LOG_INJECTION · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
HTTP Response Splitting is a security vulnerability where an attacker manipulates an HTTP response by injecting Carriage Return (CR) and Line Feed (LF) characters (collectively called CRLF) into a response header. These characters mark the end of a header and the start of a new line in HTTP responses.

## Exploit payloads (from PayloadsAllTheThings)
- `HTTP/1.1 200 OK`
- `Content-Type: text/html`
- `Set-Cookie: sessionid=abc123`
- `HTTP/1.1 200 OK`
- `Content-Type: text/html`
- `Set-Cookie: sessionid=value`
- `Set-Cookie: admin=true`
- `http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0ACo`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=CRLF%20/%20HTTP%20Splitting%20/%20Log
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [CRLF (%0D%0A) Injection](https://hacktricks.wiki/en/pentesting-web/crlf-0d-0a)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
