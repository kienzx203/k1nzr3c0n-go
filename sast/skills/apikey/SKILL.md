# API Key / Secret Leaks — @keyhunter skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
nuclei -t token-spray/ -var token=token_list.txt

## Exploit payloads (from PayloadsAllTheThings)
- `nuclei -t token-spray/ -var token=token_list.txt`
- `api_key = "1234567890abcdef"`
- `docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity`
- `docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.co`
- `docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker --image trufflesecurity/`
- `patterns:`
- `- pattern:`
- `name: AWS API Gateway`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=API%20Key%20/%20Secret%20Leaks
- HackTricks Cloud: https://cloud.hacktricks.wiki/
