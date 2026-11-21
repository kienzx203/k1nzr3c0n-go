# Cross-Site Leaks — @sideband skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Unlike classic CORS or XSS attacks, XS-Leaks rely on observable browser behavior:

## Exploit payloads (from PayloadsAllTheThings)
- `// Get a reference to the window`
- `var win = window.open('https://example.org');`
- `// Wait for the page to load`
- `setTimeout(() => {`
- `// Read the number of iframes loaded`
- `console.log("%d iframes detected", win.length);`
- `}, 2000);`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XS-Leak
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Cross-Site%20Leaks
- HackTricks Cloud: https://cloud.hacktricks.wiki/
