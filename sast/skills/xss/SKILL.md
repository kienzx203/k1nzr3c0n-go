# Cross-Site Scripting — @reflektor skill
> cats: XSS · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input is rendered into an HTML/JS/attribute/URL context without context-correct
encoding, so attacker script runs in the victim's browser.

## Code review — source → sink
- SINKS: raw response writes (`response.write`, `echo`, `print`), template interpolation with
  auto-escape OFF (`|safe`, `{!! !!}`, `v-html`, `dangerouslySetInnerHTML`, `Html.Raw`,
  `text/template` in Go instead of `html/template`), DOM sinks (`innerHTML`, `document.write`,
  `insertAdjacentHTML`, `eval`, `location=`, jQuery `.html()`).
- CONTEXTS: HTML body, attribute, JS string, URL, CSS — each needs a different encoder.
- SANITIZERS (SAFE): framework auto-escaping (`html/template`, Razor, Thymeleaf, React text),
  `htmlspecialchars`/`htmlentities`, OWASP Java Encoder, DOMPurify for HTML, URL-encoding for URLs.

## Exploit payloads
`<script>alert(1)</script>` · `"><img src=x onerror=alert(1)>` · attr `" onmouseover=alert(1) x="`
· JS ctx `';alert(1)//` · URL `javascript:alert(1)` · `<svg/onload=alert(1)>`.

## VERIFY
- CONFIRMED when: tainted data reaches an HTML/JS/DOM sink with **auto-escape disabled** or a
  raw sink, and no context-appropriate encoder/sanitizer is applied.
- FALSE POSITIVE when: output goes through framework auto-escaping or an explicit correct
  encoder for that context (HTML-encode for body, JS-encode for script, URL-encode for href),
  or the value is a safe fixed type (int/enum/bool).
- LIKELY when: the sink is raw but the encoding/sanitizer applied upstream is not visible, or
  the context (attribute vs JS vs URL) can't be determined.

## Remediation
Keep auto-escaping on; encode per output context; use DOMPurify for rich HTML; set CSP; avoid
`innerHTML`/`v-html`/`dangerouslySetInnerHTML` with user data.

## References
- PayloadsAllTheThings/XSS: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/

## HackTricks pages (21)

- [Abusing Service Workers](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/abusing-service-workers)
- [BrowExt - XSS Example](https://hacktricks.wiki/en/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example)
- [Chrome Cache to XSS](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/chrome-cache-to-xss)
- [DOM Invader](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-invader)
- [DOM XSS](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-xss)
- [Debugging Client-Side JavaScript](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/debugging-client-side-js)
- [Dom Clobbering](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [Iframes in XSS, CSP and SOP](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp)
- [Integer Overflow (Web Applications)](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/integer-overflow)
- [JS Hoisting](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/js-hoisting)
- [Misc JS Tricks & Relevant Info](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/other-js-tricks)
- [PDF Injection](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/pdf-injection)
- [SOME - Same Origin Method Execution](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/some-same-origin-method-execution)
- [Server Side XSS (Dynamic PDF)](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)
- [Shadow DOM](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/shadow-dom)
- [Sniff Leak](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/sniff-leak)
- [Steal Info JS](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/steal-info-js)
- [WebAssembly linear memory corruption to DOM XSS (template overwrite)](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/wasm-linear-memory-template-overwrite-xss)
- [XSS (Cross Site Scripting)](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/README)
- [XSS in Markdown](https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/xss-in-markdown)
- [XSSI (Cross-Site Script Inclusion)](https://hacktricks.wiki/en/pentesting-web/xssi-cross-site-script-inclusion)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
