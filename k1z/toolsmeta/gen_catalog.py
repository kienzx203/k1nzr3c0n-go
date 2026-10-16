#!/usr/bin/env python3
"""Generate catalog_gen.go from the Python project's TOOLS/WORDLISTS lists.

Usage: python3 gen_catalog.py <tools_catalog.json> > catalog_gen.go
"""
import json
import sys


def gstr(s):
    if s is None:
        return '""'
    return json.dumps(s, ensure_ascii=False)


def main():
    data = json.load(open(sys.argv[1]))
    out = []
    out.append("// Code generated from the Python project's tools.py TOOLS/WORDLISTS.")
    out.append("// DO NOT EDIT MANUALLY — regenerate with gen_catalog.py.")
    out.append("")
    out.append("package toolsmeta")
    out.append("")
    out.append("var generatedTools = []Tool{")
    for t in data["tools"]:
        fields = [
            f"Name: {gstr(t['name'])}",
            f"Display: {gstr(t.get('display', ''))}",
            f"Desc: {gstr(t.get('desc', ''))}",
            f"Cat: {gstr(t['cat'])}",
            f"Repo: {gstr(t.get('repo', ''))}",
        ]
        globs = t.get("asset_globs") or []
        glist = ", ".join(gstr(g) for g in globs)
        fields.append(f"AssetGlobs: []string{{{glist}}}")
        fields.append(f"AssetFmt: {gstr(t.get('asset_fmt', ''))}")
        fields.append(f"BinInArc: {gstr(t.get('bin_in_arc', ''))}")
        fields.append(f"Dest: {gstr(t.get('dest', ''))}")
        vcmd = t.get("version_cmd") or []
        vlist = ", ".join(gstr(c) for c in vcmd)
        fields.append(f"VersionCmd: []string{{{vlist}}}")
        fields.append(f"VersionRe: {gstr(t.get('version_re', ''))}")
        fields.append(f"PyPI: {gstr(t.get('pypi', ''))}")
        fields.append(f"GitDir: {gstr(t.get('git_dir', ''))}")
        out.append("\t{" + ", ".join(fields) + "},")
    out.append("}")
    out.append("")
    out.append("var generatedWordlists = []Wordlist{")
    for w in data["wordlists"]:
        fields = [
            f"Name: {gstr(w['name'])}",
            f"Display: {gstr(w.get('display', ''))}",
            f"File: {gstr(w['file'])}",
            f"URL: {gstr(w['url'])}",
            f"Extract: {gstr(w.get('extract') or '')}",
            f"ExtractGlob: {gstr(w.get('extract_glob') or '')}",
        ]
        out.append("\t{" + ", ".join(fields) + "},")
    out.append("}")
    out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
