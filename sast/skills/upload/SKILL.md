# Unrestricted File Upload — @dropper skill
> cats: UNRESTRICTED_UPLOAD · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Here is a list of the default extensions for web shell pages in the selected languages (PHP, ASP, JSP).

## Exploit payloads (from PayloadsAllTheThings)
- `.php`
- `.php3`
- `.php4`
- `.php5`
- `.php7`
- `.pht`
- `.phps`
- `.phar`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Unrestricted%20File%20Upload
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [[Defender-quarantined]](https://hacktricks.wiki/en/pentesting-web/file-upload/README)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
