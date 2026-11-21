# XPath / XQuery / XXE — @xcross skill
> cats: XPATHI, XQUERYI, XML_INJECTION, XXE · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input alters an XPath/XQuery expression, or an XML parser resolves external entities
(XXE) → data disclosure, SSRF, DoS.

## Code review — source → sink
- XPATH/XQUERY SINKS: `XPath.evaluate(expr)`, `selectNodes/selectSingleNode`, `lxml` `.xpath`,
  PHP `DOMXPath::query`, .NET `SelectNodes`, concatenated expressions.
- XXE SINKS: XML parsers with external entities/DTD enabled — `DocumentBuilderFactory`,
  `SAXParser`, `XMLReader`, `Unmarshaller`, `lxml.etree` (resolve_entities), PHP `libxml`
  (pre-`libxml_disable_entity_loader`), .NET `XmlReader` with `DtdProcessing.Parse`.
- SANITIZERS (SAFE): parameterized XPath (`XPathVariableResolver`, variable `$x`), disable DTD/
  external entities (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`, `XXE` features off),
  allow-list.

## Exploit payloads
XPath `' or '1'='1` · `']|//user/*|a['` · auth bypass `' or 1=1 or ''='` ·
XXE `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>` · OOB/SSRF entity to `http://169.254.169.254`.

## VERIFY
- CONFIRMED when: tainted input is **concatenated into an XPath/XQuery expression**, OR an XML
  parser has **DTD/external entities enabled** and parses untrusted XML.
- FALSE POSITIVE when: XPath uses variable binding, or the parser disables DTD/external entities
  / sets secure-processing, or input is allow-listed.
- LIKELY when: the sink is present but entity settings / expression construction aren't visible.

## Remediation
Use XPath variables (no string-building); disable DTD + external entities; enable secure
processing; validate against a schema.

## References
- PayloadsAllTheThings/XPATH: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection
- XXE: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- HackTricks XXE: https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html

## HackTricks pages (1)

- [XPATH injection](https://hacktricks.wiki/en/pentesting-web/xpath-injection)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
