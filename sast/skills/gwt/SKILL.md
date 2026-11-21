# GWT Exposure — @gwtprobe skill
> cats: (advisory — no static taint rule yet) · severity: low
> sources: PayloadsAllTheThings, HackTricks

## What it is
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup

## Exploit payloads (from PayloadsAllTheThings)
- `./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup`
- `./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js`
- `./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080`
- `./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js`
- `./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login`
- `./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc `
- `./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login `
- `./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rp`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Google%20Web%20Toolkit
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=GWT%20Exposure
- HackTricks Cloud: https://cloud.hacktricks.wiki/
