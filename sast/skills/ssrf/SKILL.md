# Server-Side Request Forgery — @gateway skill
> cats: SSRF · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
The attacker controls the host/URL of a request the server makes, reaching internal services,
cloud metadata, or local files.

## Code review — source → sink
- SINKS: HTTP clients with a user URL — Go `http.Get/NewRequest`, Java `URL.openConnection`,
  `HttpClient`/`RestTemplate`/`WebClient`, Python `requests.get`/`urllib`, PHP `curl_exec`/
  `file_get_contents($url)`, Node `fetch`/`axios`; also webhooks, image/PDF fetchers, XML/SVG
  parsers that fetch, URL previews.
- SANITIZERS (SAFE): allow-list of hosts/schemes, resolve DNS then block private/link-local
  ranges (169.254/10./127./::1/metadata), disable redirects, no raw user host.

## Exploit payloads
`http://169.254.169.254/latest/meta-data/` (AWS IMDS) · `http://metadata.google.internal/` ·
`http://127.0.0.1:port` · `file:///etc/passwd` · `gopher://` · DNS-rebinding · decimal/hex IPs ·
`http://[::1]` · redirect to internal.

## VERIFY
- CONFIRMED when: attacker controls the request host/URL and there is **no scheme/host
  allow-list and no private-range block**; redirects followed.
- FALSE POSITIVE when: the host is fixed/constant, or strictly allow-listed, or only a path/query
  on a fixed base host is user-controlled (not the host).
- LIKELY when: some validation exists but is bypassable (blocklist-only, no DNS re-check, no
  redirect handling) or the base URL construction is not fully visible.

## Remediation
Allow-list hosts+schemes; resolve + reject private/link-local/metadata IPs; disable auto-redirects;
isolate egress; drop `file://`/`gopher://`.

## References
- PayloadsAllTheThings/SSRF: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/
- Cloud metadata (hacktricks-cloud): https://cloud.hacktricks.wiki/en/pentesting-cloud/

## HackTricks pages (4)

- [Cloud SSRF](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf)
- [SSRF (Server Side Request Forgery)](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/README)
- [SSRF Vulnerable Platforms](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/ssrf-vulnerable-platforms)
- [URL Format Bypass](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
