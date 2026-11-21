# Exposed Mgmt Interface — @adminleak skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Insecure Management Interface vulnerabilities arise when administrative interfaces of systems or applications are improperly secured, allowing unauthorized or malicious users to gain access, modify configurations, or exploit sensitive operations. These interfaces are often critical for maintaining, monitoring, and controlling systems and must be secured rigorously.

## Exploit payloads (from PayloadsAllTheThings)
- `nuclei -t http/default-logins -u https://example.com`
- `nuclei -t http/exposed-panels -u https://example.com`
- `nuclei -t http/exposures -u https://example.com`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Management%20Interface
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Exposed%20Mgmt%20Interface
- HackTricks Cloud: https://cloud.hacktricks.wiki/
