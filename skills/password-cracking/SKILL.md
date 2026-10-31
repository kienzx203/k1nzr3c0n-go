---
name: password-cracking
description: Use when you have captured hashes or credential material to crack offline — identifying the hash type, choosing a hashcat/john attack (dictionary+rules, mask, hybrid), picking wordlists/rules, and deciding when NOT to crack (pass-the-hash/relay instead). Authorized engagements only.
metadata:
  type: offensive
  phase: credential-access
  tools: hashcat, john, hashid, name-that-hash, haiti
---

# Password / Hash Cracking

Offline cracking of hashes you captured in-scope. Cracking is **credential-access tradecraft** — it
reveals weak-password risk and unlocks reuse across services. Crack **offline** on your own box; do
not turn this into online spraying (that is a different, noisy, lockout-prone technique).

## 1. Identify the hash first
Wrong mode = wasted GPU. Identify before you crack:
- `hashcat --identify <file>` (built-in), or `hashid` / `name-that-hash` / `haiti`.
- Know the context, it narrows it fast:
  - Linux `/etc/shadow`: `$6$`=sha512crypt (m 1800), `$5$`=sha256crypt (7400), `$y$`=yescrypt.
  - Windows: NTLM (m 1000), NetNTLMv2 from responder/relay (5600), NetNTLMv1 (5500).
  - AD: **Kerberoast** TGS-REP `$krb5tgs$23$` (13100), **AS-REP** `$krb5asrep$23$` (18200),
    DCC2/mscash2 (2100).
  - Web: bcrypt `$2a/2b$` (3200, slow — small list only), MD5 (0), SHA1 (100), SHA256 (1400).
  - Files: ZIP (via `zip2john`), Office (`office2john`), KeePass (`keepass2john`), PDF, SSH keys.

## 2. Choose the attack (fastest payoff first)
1. **Dictionary + rules** — the workhorse: `hashcat -m <mode> hashes.txt rockyou.txt -r best64.rule`.
   Escalate rules: `best64` → `OneRuleToRuleThemAll` → `dive`. Add target-specific words (company,
   product, year) to a custom list.
2. **Mask / brute** for known patterns: `-a 3 ?u?l?l?l?l?d?d?d?d` (e.g. `Summer2026!`). Build masks
   from the org's observed policy; full brute only for short/fast hashes.
3. **Hybrid**: wordlist + mask (`-a 6 words.txt ?d?d?d?s`) for `word + digits/symbol` habits.
4. **Combinator** (`-a 1`) for passphrase-style `word1word2`.

## 3. Wordlists & rules
- `rockyou.txt` first (SecLists `/usr/share/seclists/Passwords/`). Then `weakpass`, `rockyou2024`,
  crackstation, and **SecLists** leaked/corporate lists. Keywords/CeWL-scraped from the target site.
- Rules multiply a list cheaply — prefer `list + good rule` over bigger raw lists.
- GPU (hashcat) for speed; CPU/john for exotic formats (`john --format=... --wordlist=...`).

## 4. When NOT to crack (do this instead)
- **NTLM / NetNTLMv2**: you often don't need the plaintext — **pass-the-hash** (NTLM) or **relay**
  (NetNTLMv2, if signing is off) is faster. See the network-attack / active-directory-attack skills.
- **Kerberos**: Kerberoast/AS-REP hashes DO crack offline — service accounts with weak passwords are
  the win; request tickets only for in-scope SPNs.
- bcrypt/argon2/scrypt are deliberately slow: only a tiny targeted list, don't brute.

## OPSEC & discipline
- Crack **offline** — capturing (responder/secretsdump/kerberoast) is the in-network step; keep it
  scoped and quiet (watch for honey-accounts/roast canaries). Record cracked creds as a **cred matrix**
  for reuse testing, each use logged.
- Report weak/cracked credentials via finding-discipline (proof = the cracked plaintext + where it
  worked), never dump plaintext into long-term context. Authorized scope only.
