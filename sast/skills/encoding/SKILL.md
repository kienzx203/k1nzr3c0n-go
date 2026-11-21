# Encoding Confusion — @charbreak skill
> cats: (advisory — no static taint rule yet) · severity: low
> sources: PayloadsAllTheThings, HackTricks

## What it is
Unicode is a universal character encoding standard used to represent text from virtually every writing system in the world. Each character (letters, numbers, symbols, emojis) is assigned a unique code point (for example, U+0041 for "A"). Unicode encoding formats like UTF-8 and UTF-16 specify how these code points are stored as bytes.

## Exploit payloads (from PayloadsAllTheThings)
- `import unicodedata`
- `string = "ᴾᵃʸˡᵒᵃᵈˢ𝓐𝓵𝓵𝕋𝕙𝕖𝒯𝒽𝒾𝓃ℊ𝓈"`
- `print ('NFC: ' + unicodedata.normalize('NFC', string))`
- `print ('NFD: ' + unicodedata.normalize('NFD', string))`
- `print ('NFKC: ' + unicodedata.normalize('NFKC', string))`
- `print ('NFKD: ' + unicodedata.normalize('NFKD', string))`
- `SELECT 'a' = 'ᵃ';`
- `+-------------+`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Encoding%20Transformations
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=Encoding%20Confusion
- HackTricks Cloud: https://cloud.hacktricks.wiki/
