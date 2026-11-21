# LDAP Injection — @dirwraith skill
> cats: LDAPI · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input is concatenated into an LDAP search filter or DN, letting the attacker alter
the query (auth bypass, attribute disclosure).

## Code review — source → sink
- SINKS: `DirContext.search(filter)`, `InitialDirContext`, `ldap_search`/`ldap_bind` (PHP),
  `ldap3`/`python-ldap` search with f-string filters, .NET `DirectorySearcher.Filter`,
  Go LDAP `SearchRequest{Filter: ...}`.
- Filter metachars: `( ) * \ / NUL` ; DN metachars: `, + " \ < > ; =`.
- SANITIZERS (SAFE): `encodeForLDAP`/`encodeForDN` (OWASP ESAPI), framework filter builders
  with bound assertions, allow-list of attribute names, numeric/enum validation.

## Exploit payloads
`*` (match all) · `*)(uid=*))(|(uid=*` · auth bypass `*)(|(password=*))` · `admin)(|(|` ·
blind boolean `)(cn=a*)`.

## VERIFY
- CONFIRMED when: tainted input is **concatenated into a filter/DN string** with no LDAP escaping.
- FALSE POSITIVE when: the input is LDAP-escaped (`encodeForLDAP`/`escapeDN`), bound via a
  safe filter builder, or allow-listed.
- LIKELY when: it reaches an LDAP search but escaping isn't visible.

## Remediation
Escape with ESAPI `encodeForLDAP`/`encodeForDN`; use parameterized filter assertions; allow-list
attributes; least-privilege bind account.

## References
- PayloadsAllTheThings/LDAP Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html

## HackTricks pages (1)

- [LDAP Injection](https://hacktricks.wiki/en/pentesting-web/ldap-injection)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
