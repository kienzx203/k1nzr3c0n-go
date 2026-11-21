#!/usr/bin/env python3
"""
Apply ALL of HackTricks to the agent skills — every page attributed to an agent.

- Pages under pentesting-web map to the matching vulnerability agent (by keyword);
  leftover web pages go to the general Web-Pentest agent.
- Every other HackTricks domain (network services, Windows/AD, Linux, macOS,
  binary exploitation, mobile, AI, crypto, blockchain, reversing, hardware, stego,
  methodology, privacy, generic hacking) becomes one domain agent.
- Each agent's SKILL.md gets a '## HackTricks pages' section listing its pages
  (idempotent — regenerated each run). A coverage ledger proves 0 pages missed.

Writes agent_c/hacktricks_agents.json (domain agents) and updates skills/*.
Run:  python3 agent_c/gen_hacktricks.py
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HT = os.path.join(ROOT, "skills", "hacktricks", "repo")
SKILLS = os.path.join(ROOT, "skills")
OUT = os.path.join(ROOT, "agent_c", "hacktricks_agents.json")
SITE = "https://hacktricks.wiki/en/"
MARK = "## HackTricks pages"

# web page path keyword -> existing vuln agent id (first match wins, order matters)
WEB = [
    ("sql-injection", "sqli"), ("nosql", "nosqli"), ("ldap-injection", "ldap"),
    ("xpath", "xpath"), ("xss-cross-site-scripting", "xss"), ("dom-xss", "xss"),
    ("xxe", "xxe"), ("ssrf", "ssrf"), ("command-injection", "cmdi"),
    ("argument-injection", "cmdi"), ("ssti", "ssti"), ("el-expression-language", "ssti"),
    ("file-inclusion", "lfi"), ("path-traversal", "path"), ("directory-traversal", "path"),
    ("file-upload", "upload"), ("deserialization", "deserial"), ("open-redirect", "redirect"),
    ("crlf", "crlf"), ("csrf", "csrf"), ("cors", "cors"), ("clickjacking", "clickjacking"),
    ("jwt", "jwt"), ("json-web-token", "jwt"), ("oauth", "oauth"), ("saml", "saml"),
    ("graphql", "graphql"), ("prototype-pollution", "protopoll"), ("race-condition", "race"),
    ("regular-expression", "redos"), ("web-cache", "cachedecept"), ("cache-deception", "cachedecept"),
    ("websocket", "websocket"), ("web-sockets", "websocket"), ("request-smuggling", "smuggling"),
    ("http-request-smuggling", "smuggling"), ("parameter-pollution", "hpp"),
    ("idor", "idor"), ("dependency-confusion", "depconf"), ("dom-clobbering", "domclob"),
    ("mass-assignment", "massassign"), ("captcha", "bruteforce"), ("rate-limit", "bruteforce"),
    ("account-takeover", "ato"), ("reset-password", "ato"), ("2fa", "ato"),
    ("csv-injection", "csvi"), ("formula-injection", "csvi"), ("css-injection", "cssi"),
    ("hop-by-hop", "smuggling"), ("cache-poisoning", "cachedecept"), ("type-juggling", "typejuggle"),
    ("php-tricks", "typejuggle"), ("ssi-server-side", "ssi"), ("esi-injection", "ssi"),
    ("xslt", "xslt"), ("ldap", "ldap"), ("tabnabbing", "tabnabbing"),
    ("registration-vulnerabilities", "ato"), ("reverse-tab-nabbing", "tabnabbing"),
    ("sql", "sqli"), ("xss", "xss"),
]

# top-level HackTricks domain -> new domain agent (id, name, handle, icon, sev)
DOMAINS = {
    "pentesting-web":                     ("websec", "Web Pentest (misc)", "webwraith", "⌬", "high"),
    "network-services-pentesting":        ("netsvc", "Network Services Pentest", "portreaper", "⇵", "high"),
    "generic-methodologies-and-resources":("methodology", "Methodology & Recon", "reconwraith", "◈", "medium"),
    "windows-hardening":                  ("winpriv", "Windows / AD Privesc", "ntlmghost", "⊞", "high"),
    "binary-exploitation":                ("binexp", "Binary Exploitation", "pwnsmith", "⊹", "high"),
    "macos-hardening":                    ("macos", "macOS Security", "applecore", "◖", "medium"),
    "linux-hardening":                    ("linpriv", "Linux Privesc", "rootpath", "⌸", "high"),
    "mobile-pentesting":                  ("mobile", "Mobile (Android/iOS)", "droidfruit", "▣", "medium"),
    "AI":                                 ("aipent", "AI / LLM Pentest", "promptreaper", "◉", "high"),
    "privacy":                            ("privacy", "Privacy / OPSEC", "ghostmask", "◐", "low"),
    "generic-hacking":                    ("generichack", "Generic Hacking / Pivoting", "pivoteer", "⇄", "medium"),
    "reversing":                          ("reversing", "Reverse Engineering", "disasm", "⊶", "medium"),
    "hardware-physical-access":           ("hardware", "Hardware / Physical", "jtaghost", "⎓", "medium"),
    "crypto":                             ("crypto", "Crypto Attacks", "cipherbane", "⊗", "medium"),
    "blockchain":                         ("blockchain", "Blockchain / Web3", "chainwraith", "⬠", "medium"),
    "stego":                              ("stego", "Steganography / Forensics", "stegwraith", "▦", "low"),
    "todo":                               ("methodology", None, None, None, None),  # fold into methodology
}
SKIP_DIRS = {"banners", "files", "welcome"}
SKIP_NAMES = {"SUMMARY.md"}

VERIFY_DOMAIN = """- Use these pages as the attack/review reference for this domain. When this agent
  reviews a target, CONFIRM a finding only with concrete evidence from the code/config;
  treat name-only or version-only signals as LIKELY until verified."""


def title_of(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                m = re.match(r"^#\s+(.+)", ln.strip())
                if m:
                    return re.sub(r"[`*]", "", m.group(1)).strip()[:90]
    except OSError:
        pass
    return os.path.basename(path)[:-3].replace("-", " ")


def web_agent(rel):
    low = rel.lower()
    for kw, aid in WEB:
        if kw in low:
            return aid
    return "websec"


def assign(rel):
    top = rel.split("/", 1)[0]
    if top == "pentesting-web":
        return web_agent(rel)
    dom = DOMAINS.get(top)
    return dom[0] if dom else "methodology"


def strip_section(md):
    i = md.find("\n" + MARK)
    return md[:i].rstrip() + "\n" if i != -1 else md.rstrip() + "\n"


def main():
    pages = {}   # agent_id -> list[(title, url)]
    total = skipped = 0
    for dp, dns, fns in os.walk(HT):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in fns:
            if not fn.endswith(".md") or fn in SKIP_NAMES:
                continue
            rel = os.path.relpath(os.path.join(dp, fn), HT).replace(os.sep, "/")
            top = rel.split("/", 1)[0]
            if top in SKIP_DIRS or top == "LICENSE.md" or fn == "README.md" and "/" not in rel:
                skipped += 1
                continue
            total += 1
            aid = assign(rel)
            url = SITE + rel[:-3]
            pages.setdefault(aid, []).append((title_of(os.path.join(dp, fn)), url))

    # domain agents registry
    reg, seen = [], set()
    for top, (aid, name, handle, icon, sev) in DOMAINS.items():
        if name is None or aid in seen:
            continue
        seen.add(aid)
        reg.append({"id": aid, "name": name, "handle": handle, "icon": icon,
                    "sev": sev, "kind": "pentest",
                    "desc": "%s — HackTricks knowledge base." % name})
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, ensure_ascii=False, indent=1)

    # write / update skills
    dom_ids = {r["id"] for r in reg}
    for aid, plist in pages.items():
        plist.sort()
        d = os.path.join(SKILLS, aid)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "SKILL.md")
        if aid in dom_ids and not os.path.exists(p):
            meta = next(r for r in reg if r["id"] == aid)
            head = ["# %s — @%s skill" % (meta["name"], meta["handle"]),
                    "> kind: pentest · severity: %s · source: HackTricks" % meta["sev"],
                    "", "## What it is",
                    "%s. HackTricks reference pages for this domain are indexed below." % meta["name"],
                    "", "## VERIFY", VERIFY_DOMAIN, ""]
            base = "\n".join(head)
        else:
            base = strip_section(open(p, encoding="utf-8").read()) if os.path.exists(p) else "# %s skill\n" % aid
        sec = [base.rstrip(), "", "%s (%d)" % (MARK, len(plist)), ""]
        sec += ["- [%s](%s)" % (t, u) for (t, u) in plist]
        sec += ["", "## References",
                "- HackTricks: https://hacktricks.wiki/en/",
                "- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks", ""]
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sec))

    # coverage ledger
    assigned = sum(len(v) for v in pages.values())
    print("HackTricks pages total (content): %d · assigned: %d · skipped(index): %d"
          % (total, assigned, skipped))
    print("unmapped pages:", total - assigned, "(must be 0)")
    print("agents receiving pages: %d · domain agents added: %d" % (len(pages), len(reg)))
    top5 = sorted(((len(v), k) for k, v in pages.items()), reverse=True)[:8]
    print("top:", ", ".join("%s=%d" % (k, n) for n, k in top5))


if __name__ == "__main__":
    main()
