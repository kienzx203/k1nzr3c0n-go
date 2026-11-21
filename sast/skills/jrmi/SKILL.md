# Java RMI — @rmireaper skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
$ nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v

## Exploit payloads (from PayloadsAllTheThings)
- `$ nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v`
- `1089/tcp open  java-rmi Java RMI`
- `| rmi-vuln-classloader:`
- `|   VULNERABLE:`
- `|   RMI registry default configuration remote code execution vulnerability`
- `|     State: VULNERABLE`
- `|       Default configuration of RMI registry allows loading classes from remote URLs which can lead`
- `| rmi-dumpregistry:`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Java%20RMI
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Java%20RMI
- HackTricks Cloud: https://cloud.hacktricks.wiki/
