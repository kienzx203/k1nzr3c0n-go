#!/usr/bin/env python3
"""
Generate skills/<id>/SKILL.md for every agent that doesn't already have one,
using the local PayloadsAllTheThings clone as the knowledge source.

Hand-written skills are never overwritten. Run from anywhere:
    python3 agent_c/gen_skills.py
"""
import os
import re
import urllib.parse

import agents as AG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.join(ROOT, "skills", "payloads-all-the-things", "repo")

VERIFY = """- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code."""


def read_readme(d):
    for name in ("README.md", "Readme.md", "readme.md"):
        p = os.path.join(REPO, d, name)
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as fh:
                return fh.read()
    return ""


def intro(md):
    """First real prose paragraph (skip headings, badges, images, TOC)."""
    for ln in md.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "!", ">", "|", "-", "*", "<", "[![")):
            continue
        if s.startswith("[") and "](" in s:        # TOC link line
            continue
        if len(s) < 25:
            continue
        return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)[:400]
    return ""


def payloads(md, n=8):
    out, infence = [], False
    for ln in md.splitlines():
        if ln.strip().startswith("```"):
            infence = not infence
            continue
        if infence:
            s = ln.strip()
            if s and not s.startswith("#"):
                out.append(s[:100])
            if len(out) >= n:
                break
    return out


def build(agent):
    d = agent["payloads_dir"]
    md = read_readme(d) if d else ""
    desc = agent["desc"]
    itx = intro(md) or desc
    pls = payloads(md)
    url = ("https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/"
           + urllib.parse.quote(d)) if d else "https://github.com/swisskyrepo/PayloadsAllTheThings"
    ht = "https://book.hacktricks.wiki/en/search.html?q=" + urllib.parse.quote(agent["name"])
    cats = ", ".join(agent["cats"]) or "(advisory — no static taint rule yet)"
    lines = [
        "# %s — @%s skill" % (agent["name"], agent["handle"]),
        "> cats: %s · severity: %s" % (cats, agent["sev"]),
        "> sources: PayloadsAllTheThings, HackTricks",
        "",
        "## What it is",
        itx,
        "",
        "## Exploit payloads (from PayloadsAllTheThings)",
    ]
    lines += (["- `%s`" % p for p in pls] if pls
              else ["See the PayloadsAllTheThings folder linked below."])
    lines += [
        "",
        "## VERIFY",
        VERIFY,
        "",
        "## References",
        "- PayloadsAllTheThings: %s" % url,
        "- HackTricks: %s" % ht,
        "- HackTricks Cloud: https://cloud.hacktricks.wiki/",
        "",
    ]
    return "\n".join(lines)


def main():
    made, kept, skipped = 0, 0, 0
    for a in AG.AGENTS:
        p = AG.skill_path(a["id"])
        if os.path.exists(p):
            kept += 1
            continue
        if not a["payloads_dir"]:
            skipped += 1
            continue
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(build(a))
        made += 1
        print("  +", a["id"])
    print("generated %d · kept %d · no-dir %d" % (made, kept, skipped))


if __name__ == "__main__":
    main()
