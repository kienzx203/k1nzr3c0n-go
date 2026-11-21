# Reverse Tabnabbing — @tabghost skill
> cats: (advisory — no static taint rule yet) · severity: low
> sources: PayloadsAllTheThings, HackTricks

## What it is
When tabnabbing, the attacker searches for links that are inserted into the website and are under his control. Such links may be contained in a forum post, for example. Once he has found this kind of functionality, it checks that the link's `rel` attribute does not contain the value `noopener` and the target attribute contains the value `_blank`. If this is the case, the website is vulnerable to t

## Exploit payloads (from PayloadsAllTheThings)
- `<a href="..." target="_blank" rel="">`
- `<a href="..." target="_blank">`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Tabnabbing
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Reverse%20Tabnabbing
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [Reverse Tab Nabbing](https://hacktricks.wiki/en/pentesting-web/reverse-tab-nabbing)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
