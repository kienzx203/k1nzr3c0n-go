# Prototype Pollution — @protoghost skill
> cats: (advisory — no static taint rule yet) · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
In JavaScript, prototypes are what allow objects to inherit features from other objects. If an attacker is able to add or modify properties of `Object.prototype`, they can essentially affect all objects that inherit from that prototype, potentially leading to various kinds of security risks.

## Exploit payloads (from PayloadsAllTheThings)
- `var myDog = new Dog();`
- `// Points to the function "Dog"`
- `myDog.constructor;`
- `// Points to the class definition of "Dog"`
- `myDog.constructor.prototype;`
- `myDog.__proto__;`
- `myDog["__proto__"];`
- `let config = {`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Prototype%20Pollution
- HackTricks Cloud: https://cloud.hacktricks.wiki/
