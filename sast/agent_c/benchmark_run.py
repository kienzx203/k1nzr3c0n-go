#!/usr/bin/env python3
"""
Benchmark runner (efficient): parse the whole corpus ONCE, then run the taint
engine PER FILE (small self-contained graphs) to avoid one giant fixpoint.

    python3 agent_c/benchmark_run.py <lang> <src_dir> <out.json>
"""
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "agent_a"))
import engine                     # noqa: E402
from callgraph import CallGraph   # noqa: E402
import run_lang                   # noqa: E402

DB = os.path.join(ROOT, "taint_spec.db")


def file_of(pos):
    return pos.rsplit(":", 2)[0] if pos and ":" in pos else pos


def main():
    lang, src, out = sys.argv[1], sys.argv[2], sys.argv[3]
    fam = run_lang.LANG_FAMILY.get(lang, lang)
    spec = engine.load_spec(DB, fam)
    cats = run_lang.DEFAULT_CATS
    ir = run_lang.extract_ir(lang, src)     # one parse of the whole corpus
    groups = defaultdict(list)
    for f in ir.get("functions", []):
        groups[file_of(f.get("pos", ""))].append(f)
    findings = []
    nfiles = 0
    for path, funcs in groups.items():
        nfiles += 1
        mini = {"functions": funcs}
        cg = CallGraph(mini)
        az = engine.Analyzer(mini, spec, cg=cg)
        findings += az.run(cats)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, ensure_ascii=False)
    print(f"parsed functions: {len(ir.get('functions', []))} in {nfiles} files; "
          f"findings: {len(findings)} -> {out}")


if __name__ == "__main__":
    main()
