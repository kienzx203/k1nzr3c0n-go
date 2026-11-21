# SAML Injection — @assertion skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
A SAML Response should contain the `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`.

## Exploit payloads (from PayloadsAllTheThings)
- `<?xml version="1.0" encoding="UTF-8"?>`
- `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:7`
- `<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.`
- `<saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">`
- `<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />`
- `</saml2p:Status>`
- `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id3945308408248426654986295`
- `<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=SAML%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (2)

- [SAML Attacks](https://hacktricks.wiki/en/pentesting-web/saml-attacks/README)
- [SAML Basics](https://hacktricks.wiki/en/pentesting-web/saml-attacks/saml-basics)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
