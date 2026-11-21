# Virtual Host / Host Header — @vhoster skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo

## Exploit payloads (from PayloadsAllTheThings)
- `prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo`
- `gobuster vhost -u https://example.com -w /path/to/wordlist.txt`
- `GET / HTTP/1.1`
- `Host: example.com`
- `<VirtualHost *:80>`
- `ServerName site-a.com`
- `DocumentRoot /var/www/a`
- `</VirtualHost>`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Virtual%20Hosts
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Virtual%20Host%20/%20Host%20Header
- HackTricks Cloud: https://cloud.hacktricks.wiki/
