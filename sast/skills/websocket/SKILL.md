# WebSocket Security — @socketeer skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
WebSockets start as a normal `HTTP/1.1` request and then upgrade the connection to use the WebSocket protocol.

## Exploit payloads (from PayloadsAllTheThings)
- `GET /chat HTTP/1.1`
- `Host: example.com:80`
- `Upgrade: websocket`
- `Connection: Upgrade`
- `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`
- `Sec-WebSocket-Version: 13`
- `HTTP/1.1 101 Switching Protocols`
- `Upgrade: websocket`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=WebSocket%20Security
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [WebSocket Attacks](https://hacktricks.wiki/en/pentesting-web/websocket-attacks)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
