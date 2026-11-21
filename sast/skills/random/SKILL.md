# Insecure Randomness — @entropy skill
> cats: (advisory — no static taint rule yet) · severity: medium
> sources: PayloadsAllTheThings, HackTricks

## What it is
Insecure randomness arises when the source of randomness or the method of generating random values is not sufficiently unpredictable. This can lead to predictable outputs, which can be exploited by attackers. Below, we examine common methods that are prone to insecure randomness, including time-based seeds, GUIDs, UUIDs, MongoDB ObjectIds, and the `uniqid()` function.

## Exploit payloads (from PayloadsAllTheThings)
- `import random`
- `import time`
- `seed = int(time.time())`
- `random.seed(seed)`
- `print(random.randint(1, 100))`
- `import random`
- `import time`
- `seed = int(time.mktime(time.strptime('2024-11-10 13:37', '%Y-%m-%d %H:%M')))`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Randomness
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Insecure%20Randomness
- HackTricks Cloud: https://cloud.hacktricks.wiki/
