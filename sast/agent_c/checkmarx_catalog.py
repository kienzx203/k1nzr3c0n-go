#!/usr/bin/env python3
"""Checkmarx coverage catalog (extracted from CxSAST QueryHierarchy.xml): the full
set of vulnerability queries + role base-queries (source/sink/sanitizer) across all
22 Checkmarx languages. Used as a COVERAGE map so SAST_k1nz does not miss a vuln
class, and to tag source/sink/sanitize roles per language."""
import json
import os

_HERE = os.path.dirname(__file__)
_PATH = os.path.join(_HERE, "checkmarx_catalog.json")


def load():
    with open(_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def languages():
    return sorted(load().keys())


def vuln_types():
    """Distinct vulnerability short-names across all languages (lang/group prefix
    stripped), e.g. SQL_Injection, Stored_XSS, Command_Injection."""
    cat = load()
    out = set()
    for d in cat.values():
        for q in d.get("vulns", []):
            out.add(q.rsplit(".", 1)[-1])
    return sorted(out)


def roles(lang):
    d = load().get(lang, {})
    return {"sources": d.get("sources", []), "sinks": d.get("sinks", []),
            "sanitizers": d.get("sanitizers", [])}


def stats():
    cat = load()
    return {lang: {"vulns": d["vuln_count"], "sources": len(d["sources"]),
                   "sinks": len(d["sinks"]), "sanitizers": len(d["sanitizers"])}
            for lang, d in cat.items()}


if __name__ == "__main__":
    print("languages:", len(languages()))
    print("distinct vuln types:", len(vuln_types()))
    tot = sum(v["vulns"] for v in stats().values())
    print("total vuln queries:", tot)
