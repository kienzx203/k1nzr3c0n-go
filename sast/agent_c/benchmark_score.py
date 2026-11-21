#!/usr/bin/env python3
"""
Score Agent A findings against the OWASP Benchmark ground truth (Tuần 4).

    python3 agent_c/benchmark_score.py <expectedresults.csv> <findings.json>

Computes, per taint-flow category and overall: TP / FN / FP / TN, recall,
precision, and the OWASP Youden score (TPR - FPR). Non-flow categories
(hash, crypto, weakrand, trustbound, securecookie) are reported as OUT-OF-SCOPE
(pattern rules, not source→sink) and excluded from the recall figure.
"""
import csv
import json
import re
import sys
from collections import defaultdict

FLOW_CATS = {"sqli", "cmdi", "xss", "pathtraver", "ldapi", "xpathi"}
NONFLOW = {"hash", "crypto", "weakrand", "trustbound", "securecookie"}
# tool category -> benchmark category
TOOLMAP = {
    "SQLI": "sqli", "INJECTION": "sqli", "NOSQLI": "sqli",
    "CMDI": "cmdi", "XSS": "xss", "PATH": "pathtraver",
    "LDAPI": "ldapi", "XPATHI": "xpathi",
}
TEST_RE = re.compile(r"(BenchmarkTest\d+)")


def main():
    csv_path, json_path = sys.argv[1], sys.argv[2]
    truth = {}
    with open(csv_path) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name = row[0].strip()
            cat = row[1].strip()
            real = row[2].strip().lower() == "true"
            truth[name] = (cat, real)

    findings = json.load(open(json_path))
    flagged_any = defaultdict(bool)                 # test -> any finding
    flagged_cat = defaultdict(set)                  # test -> set(mapped cats)
    for f in findings:
        m = TEST_RE.search(f.get("pos", "") or f.get("func", ""))
        if not m:
            continue
        t = m.group(1)
        flagged_any[t] = True
        mc = TOOLMAP.get(f.get("category", ""))
        if mc:
            flagged_cat[t].add(mc)

    # per-category confusion (category-aware)
    per = defaultdict(lambda: dict(TP=0, FN=0, FP=0, TN=0))
    agn = defaultdict(lambda: dict(TP=0, FN=0, FP=0, TN=0))
    for name, (cat, real) in truth.items():
        if cat not in FLOW_CATS:
            continue
        hit_cat = cat in flagged_cat.get(name, set())
        hit_any = flagged_any.get(name, False)
        for tbl, hit in ((per, hit_cat), (agn, hit_any)):
            if real and hit:
                tbl[cat]["TP"] += 1
            elif real and not hit:
                tbl[cat]["FN"] += 1
            elif not real and hit:
                tbl[cat]["FP"] += 1
            else:
                tbl[cat]["TN"] += 1

    def rec(d):
        return d["TP"] / (d["TP"] + d["FN"]) if d["TP"] + d["FN"] else 0.0

    def prec(d):
        return d["TP"] / (d["TP"] + d["FP"]) if d["TP"] + d["FP"] else 0.0

    print("## OWASP Benchmark — Agent A (Java tree-sitter frontend)\n")
    print(f"findings parsed: {len(findings)} | flagged files: {len(flagged_any)}\n")
    print("Category-AWARE (finding category must match the test's CWE category):")
    hdr = f"  {'cat':<11}{'#real':>6}{'TP':>5}{'FN':>5}{'FP':>5}{'recall':>9}{'prec':>8}"
    print(hdr)
    tot = dict(TP=0, FN=0, FP=0, TN=0)
    for cat in sorted(FLOW_CATS):
        d = per[cat]
        for k in tot:
            tot[k] += d[k]
        print(f"  {cat:<11}{d['TP']+d['FN']:>6}{d['TP']:>5}{d['FN']:>5}{d['FP']:>5}"
              f"{rec(d):>9.2%}{prec(d):>8.2%}")
    print(f"  {'OVERALL':<11}{tot['TP']+tot['FN']:>6}{tot['TP']:>5}{tot['FN']:>5}{tot['FP']:>5}"
          f"{rec(tot):>9.2%}{prec(tot):>8.2%}")
    # agnostic overall
    ta = dict(TP=0, FN=0, FP=0, TN=0)
    for cat in FLOW_CATS:
        for k in ta:
            ta[k] += agn[cat][k]
    print(f"\nCategory-AGNOSTIC overall (flagged anywhere, ignore category):"
          f"  recall={rec(ta):.2%}  precision={prec(ta):.2%}")
    tpr = rec(tot)
    fpr = tot["FP"] / (tot["FP"] + tot["TN"]) if tot["FP"] + tot["TN"] else 0.0
    print(f"Youden score (TPR - FPR), category-aware: {tpr - fpr:.3f}")
    print(f"\nOut-of-scope (non-flow, pattern rules, excluded): {sorted(NONFLOW)}")


if __name__ == "__main__":
    main()
