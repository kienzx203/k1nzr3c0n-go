#!/usr/bin/env python3
"""Consolidated completeness audit: PayloadsAllTheThings + HackTricks(+Cloud)
coverage, and agent<->skill integrity. Prints a PASS/FAIL verdict.

    python3 agent_c/audit_agents.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import agents as AG  # noqa: E402

ROOT = os.path.dirname(HERE)
SK = AG.SKILLS_DIR
PATT = os.path.join(SK, "payloads-all-the-things", "repo")
HT = os.path.join(SK, "hacktricks", "repo")
HTC = os.path.join(SK, "hacktricks", "repo-cloud")
NON_VULN = {"Methodology and Resources"}
fails = []


def check(name, ok, detail=""):
    print(("  ✓ " if ok else "  ✗ ") + name + (("  — " + detail) if detail and not ok else ""))
    if not ok:
        fails.append(name)


# 1) every agent -> skill file with a usable VERIFY focus
noskill = [a["id"] for a in AG.AGENTS if not AG.skill_text(a["id"])]
noverify = [a["id"] for a in AG.AGENTS
            if "verify" not in AG.skill_focus(a["id"], "").lower()]
check("every agent has a skill file", not noskill, ",".join(noskill))
check("every skill has a usable VERIFY focus", not noverify, ",".join(noverify))

# 2) PayloadsAllTheThings: every vuln dir owned by an agent
if os.path.isdir(PATT):
    live = {d for d in os.listdir(PATT)
            if os.path.isdir(os.path.join(PATT, d)) and not d.startswith(("_", "."))
            and d not in NON_VULN}
    have = {a.get("payloads_dir") for a in AG.AGENTS if a.get("payloads_dir")}
    miss = sorted(live - have)
    check("PayloadsAllTheThings vuln dirs all mapped (%d)" % len(live), not miss, ",".join(miss))
else:
    print("  … PayloadsAllTheThings repo not present, skipping")

# 3) HackTricks main: every content page attributed to some agent
if os.path.isdir(HT):
    pages = set()
    for dp, dns, fns in os.walk(HT):
        dns[:] = [d for d in dns if d not in ("banners", "files", "welcome") and not d.startswith(".")]
        for fn in fns:
            if fn.endswith(".md") and fn not in ("SUMMARY.md", "LICENSE.md"):
                rel = os.path.relpath(os.path.join(dp, fn), HT).replace(os.sep, "/")
                if rel.split("/", 1)[0] in ("banners", "files") or rel == "README.md":
                    continue
                pages.add("https://hacktricks.wiki/en/" + rel[:-3])
    embedded = set()
    for a in AG.AGENTS:
        for m in re.findall(r"\]\((https://hacktricks\.wiki/en/[^)]+)\)", AG.skill_text(a["id"])):
            embedded.add(m)
    missing = pages - embedded
    check("HackTricks pages all embedded (%d, unmapped=%d)" % (len(pages), len(missing)),
          not missing, ",".join(sorted(missing)[:5]))
else:
    print("  … HackTricks repo not present, skipping")

# 4) HackTricks-Cloud: cloud/ci-cd topics have an agent (by count)
if os.path.isdir(HTC):
    ncloud = sum(1 for a in AG.AGENTS if a.get("kind") in ("cloud", "ci-cd"))
    check("HackTricks-Cloud agents present (%d)" % ncloud, ncloud >= 30)
else:
    print("  … HackTricks-Cloud repo not present, skipping")

from collections import Counter  # noqa: E402
print("\nagents: %d · %s" % (len(AG.AGENTS), dict(Counter(a["kind"] for a in AG.AGENTS))))
print("VERDICT:", "✅ PASS — đầy đủ, không bỏ sót" if not fails
      else "❌ FAIL: " + ", ".join(fails))
sys.exit(1 if fails else 0)
