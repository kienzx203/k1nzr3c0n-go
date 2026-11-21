# -*- coding: utf-8 -*-
"""Non-taint structural weakness detectors the taint engine cannot express.

Four classes whose bug is a PATTERN or an ABSENCE, not a source→sink flow:
  HARDCODED_SECRET  — credentials/keys/tokens baked into source
  WEAK_CRYPTO       — broken algorithms / modes / randomness / static IV-key
  MASS_ASSIGNMENT   — request data bulk-bound to a model with no allowlist
  CSRF              — state-changing handler with CSRF protection explicitly disabled

All are CANDIDATES (needs-review) the agent confirms. Tuned for low false-positive:
secrets ignore env-var / placeholder values, crypto flags only unambiguous misuse.
"""

import math
import os
import re

_SKIP = {".git", "node_modules", "vendor", ".svn", "dist", "build", "__pycache__",
         ".next", "venv", ".venv", "target", "test", "tests", "spec", "__tests__"}
_CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".java", ".kt", ".php", ".rb",
             ".go", ".cs", ".vb", ".swift", ".rs", ".c", ".cpp", ".h", ".scala",
             ".yml", ".yaml", ".properties", ".env", ".json", ".xml", ".config", ".ini"}

_PLACEHOLDER = re.compile(r"^(|x+|\.+|\*+|changeme|change_me|your[-_ ]?|example|placeholder|dummy|test|none|null|todo|xxx+|<.*>|\$\{.*\}|%.*%|\{\{.*\}\})$", re.I)
_ENVREAD = re.compile(r"getenv|process\.env|os\.environ|ENV\[|config\(|System\.getenv|Environment\.|secrets\.|vault|\.env\b")

# ── HARDCODED_SECRET ──
_SECRET_LITERAL = re.compile(
    r"(?P<key>password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key|auth[_-]?token|jwt[_-]?secret|"
    r"encryption[_-]?key|aws[_-]?secret)\s*[=:]\s*"
    r"""(?P<q>['"])(?P<val>[^'"]{6,})(?P=q)""", re.I)
_KNOWN_TOKEN = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}"), "GitHub personal access token"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
    (re.compile(r"sk_live_[0-9A-Za-z]{24,}"), "Stripe live secret key"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "hardcoded JWT"),
]

# ── WEAK_CRYPTO ──
_WEAK_CRYPTO = [
    (re.compile(r"\b(MD5|MD4|MD2)\b|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*['\"]MD5|CryptoJS\.MD5|md5\(", re.I), "MD5 (broken hash)"),
    (re.compile(r"\bSHA1\b|hashlib\.sha1|getInstance\s*\(\s*['\"]SHA-?1|CryptoJS\.SHA1|sha1\(", re.I), "SHA-1 (weak hash)"),
    (re.compile(r"\bDES\b|getInstance\s*\(\s*['\"]DES|Cipher\.DES|createCipheriv?\s*\(\s*['\"]des", re.I), "DES (broken cipher)"),
    (re.compile(r"/ECB/|['\"]ECB['\"]|AES-\d+-ECB|MODE_ECB", re.I), "ECB mode (leaks plaintext structure)"),
    (re.compile(r"\bRC4\b|getInstance\s*\(\s*['\"]RC4", re.I), "RC4 (broken cipher)"),
    (re.compile(r"Math\.random\s*\(\s*\).{0,40}(token|secret|password|key|nonce|otp|session|csrf)", re.I), "Math.random() for a security value (not cryptographically secure)"),
    (re.compile(r"(random\.random|random\.randint|mt_rand|rand\s*\()\s*.{0,30}(token|secret|password|otp|key|nonce|session)", re.I), "non-CSPRNG randomness for a security value"),
    (re.compile(r"(IV|iv|nonce)\s*[=:]\s*(b?['\"][A-Za-z0-9+/=]{4,}['\"]|new byte\[)", re.I), "static/hardcoded IV or nonce"),
    (re.compile(r"verify\s*=\s*False|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(0|false)|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true", re.I), "TLS certificate verification disabled"),
]

# ── MASS_ASSIGNMENT ──
_MASS_ASSIGN = [
    (re.compile(r"\.update\s*\(\s*(request\.(POST|data|GET)|params)\b|objects\.create\s*\(\s*\*\*\s*(request|params)"), "Django: model updated from the whole request dict"),
    (re.compile(r"(::create|->create|->fill|->update)\s*\(\s*(\$request->all\(\)|\$_(POST|REQUEST|GET)|request\(\)->all)"), "Laravel: model filled from the entire request (no $fillable allowlist)"),
    (re.compile(r"\.new\s*\(\s*params\[[^\]]+\]\s*\)|\.update\s*\(\s*params\[[^\]]+\]\s*\)|update_attributes\s*\(\s*params"), "Rails: model from params without strong-params permit"),
    (re.compile(r"Object\.assign\s*\(\s*\w+\s*,\s*req\.(body|query|params)\)|\.\.\.req\.(body|query)"), "JS: object merged with the whole request body"),
]

# ── CSRF (conservative: protection explicitly DISABLED) ──
_CSRF_DISABLED = [
    (re.compile(r"@csrf_exempt|csrf_exempt\b"), "Django @csrf_exempt"),
    (re.compile(r"->withoutMiddleware\s*\(\s*['\"].*[Cc]srf|VerifyCsrfToken.*except"), "Laravel CSRF middleware bypassed"),
    (re.compile(r"csrf\s*:\s*false|csrfProtection\s*:\s*false|\.unless\s*\(.*csrf"), "CSRF protection disabled in config"),
    (re.compile(r"protect_from_forgery\s+.*except|skip_before_action\s*:[^\n]*verify_authenticity_token"), "Rails CSRF verification skipped"),
    (re.compile(r"WebSecurity.*csrf\(\)\.disable\(\)|\.csrf\(\)\.disable\(\)"), "Spring Security CSRF disabled"),
]


def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _emit(out, cat, sev, path, rel, line, sink, note, src):
    out.append({"category": cat, "func": rel, "pos": "%s:%d" % (path, line), "line": line,
                "file": rel, "sink": sink, "sink_note": note, "source": src,
                "severity": sev, "confidence": 0.5, "weak_sanitizer": False, "interproc": False})


def scan(target):
    out = []
    for dp, dns, fns in os.walk(target):
        dns[:] = [d for d in dns if d.lower() not in _SKIP]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _CODE_EXT:
                continue
            path = os.path.join(dp, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(path, target)
            for i, ln in enumerate(lines, 1):
                if len(ln) > 500:
                    ln = ln[:500]
                # secrets: literal assignment to a secret-named key
                m = _SECRET_LITERAL.search(ln)
                if m:
                    val = m.group("val")
                    if not _PLACEHOLDER.match(val) and not _ENVREAD.search(ln) and _entropy(val) >= 2.5:
                        _emit(out, "HARDCODED_SECRET", "high", path, rel, i,
                              "hardcoded %s literal" % m.group("key").lower(),
                              "a credential/key is embedded in source; rotate it and load from env/secret-store",
                              "source literal")
                for rx, what in _KNOWN_TOKEN:
                    if rx.search(ln):
                        _emit(out, "HARDCODED_SECRET", "high", path, rel, i,
                              "hardcoded %s" % what, "a live-looking secret is embedded in source", "source literal")
                        break
                for rx, what in _WEAK_CRYPTO:
                    if rx.search(ln):
                        _emit(out, "WEAK_CRYPTO", "medium", path, rel, i,
                              what, "weak/misused cryptography — confirm it protects security-relevant data", "crypto construct")
                        break
                for rx, what in _MASS_ASSIGN:
                    if rx.search(ln):
                        _emit(out, "MASS_ASSIGNMENT", "high", path, rel, i,
                              what, "request data is bulk-bound to a model with no field allowlist — attacker can set unintended fields (e.g. is_admin)", "request body")
                        break
                for rx, what in _CSRF_DISABLED:
                    if rx.search(ln):
                        _emit(out, "CSRF", "medium", path, rel, i,
                              what, "CSRF protection is disabled here — confirm the endpoint changes state and is cookie-authenticated", "cross-site request")
                        break
    return out
