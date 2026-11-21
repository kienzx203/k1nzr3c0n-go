#!/usr/bin/env python3
"""
Deep benchmark analysis (Tuần 3-4 depth):
  (A) Does the VERIFY step improve precision? Compare recall/precision under
      three verdict policies: raw candidates / drop needs-review / confirmed-only.
  (B) ROOT-CAUSE of false negatives: for each missed real-vuln test, classify why
      (container dataflow / cross-file helper / source variant / sink not matched).

    python3 agent_c/benchmark_analyze.py <expectedresults.csv> <findings.json> <testcode_dir>
"""
import csv
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import orchestrator  # noqa: E402 (reuse heuristic_verify)

FLOW = {"sqli", "cmdi", "xss", "pathtraver", "ldapi", "xpathi"}
TOOLMAP = {"SQLI": "sqli", "INJECTION": "sqli", "NOSQLI": "sqli", "CMDI": "cmdi",
           "XSS": "xss", "PATH": "pathtraver", "LDAPI": "ldapi", "XPATHI": "xpathi"}
TEST_RE = re.compile(r"(BenchmarkTest\d+)")


def load_truth(path):
    truth = {}
    for row in csv.reader(open(path)):
        if not row or row[0].startswith("#"):
            continue
        truth[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")
    return truth


def flagged(findings, keep_verdicts=None):
    """test -> set(mapped cats) under an optional verdict filter."""
    by = defaultdict(set)
    for f in findings:
        if keep_verdicts is not None:
            v, _, _ = orchestrator.heuristic_verify(f)
            if v not in keep_verdicts:
                continue
        m = TEST_RE.search(f.get("pos", "") or f.get("func", ""))
        mc = TOOLMAP.get(f.get("category", ""))
        if m and mc:
            by[m.group(1)].add(mc)
    return by


def score(truth, by):
    TP = FN = FP = TN = 0
    for name, (cat, real) in truth.items():
        if cat not in FLOW:
            continue
        hit = cat in by.get(name, set())
        if real and hit:
            TP += 1
        elif real and not hit:
            FN += 1
        elif not real and hit:
            FP += 1
        else:
            TN += 1
    rec = TP / (TP + FN) if TP + FN else 0
    prec = TP / (TP + FP) if TP + FP else 0
    return TP, FN, FP, TN, rec, prec


def classify_fn(testdir, name):
    p = os.path.join(testdir, name + ".java")
    try:
        src = open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return "file-missing"
    # between-source-and-sink transforms the engine does not model:
    if re.search(r"\b(HashMap|Hashtable|HashSet|ArrayList|LinkedList|List<|Map<|"
                 r"\[\s*\]|StringBuilder|StringBuffer|Vector|concurrent)\b", src):
        if re.search(r"helpers\.|SeparateClass|Thing\b|IDBFactory", src):
            return "container+crossfile"
        return "container-dataflow"
    if re.search(r"helpers\.|SeparateClass|doSomething|IDBFactory", src):
        return "cross-file-helper"
    if not re.search(r"getParameter", src):
        return "source-variant"  # header/cookie/querystring/param-map etc.
    return "other (sink/transform not matched)"


def main():
    csv_path, json_path, testdir = sys.argv[1], sys.argv[2], sys.argv[3]
    truth = load_truth(csv_path)
    findings = json.load(open(json_path))

    print("## (A) Effect of the VERIFY step on recall/precision (category-aware)\n")
    print(f"  {'policy':<28}{'TP':>5}{'FN':>5}{'FP':>5}{'recall':>9}{'prec':>8}")
    policies = [("raw candidates (no verify)", None),
                ("verify: drop needs-review", {"confirmed", "likely"}),
                ("verify: confirmed-only", {"confirmed"})]
    for label, keep in policies:
        by = flagged(findings, keep)
        TP, FN, FP, TN, rec, prec = score(truth, by)
        print(f"  {label:<28}{TP:>5}{FN:>5}{FP:>5}{rec:>9.2%}{prec:>8.2%}")

    # (B) FN root causes under raw policy
    by_raw = flagged(findings, None)
    causes = defaultdict(int)
    fn_total = 0
    for name, (cat, real) in truth.items():
        if cat in FLOW and real and cat not in by_raw.get(name, set()):
            fn_total += 1
            causes[classify_fn(testdir, name)] += 1
    print(f"\n## (B) Root cause of {fn_total} false negatives (missed real vulns)\n")
    for cause, n in sorted(causes.items(), key=lambda x: -x[1]):
        print(f"  {n:>4}  ({n/fn_total:>5.1%})  {cause}")
    print("\nInterpretation: 'container-dataflow' + 'cross-file-helper' are the "
          "engine limits named in BENCHMARK.md; closing them is the recall lever.")


if __name__ == "__main__":
    main()
